//! The HPKE channel itself.
//!
//! Requests use [RFC 9180](https://datatracker.ietf.org/doc/rfc9180/) `mode_base` directly.
//! Responses use the encapsulation construction of
//! [RFC 9458 §4.4](https://datatracker.ietf.org/doc/rfc9458/) — Oblivious HTTP — because it
//! solves exactly the problem the match path has: replying to one HPKE request without a second
//! key exchange, and without reusing the request context in reverse, which RFC 9180 §9.8 forbids.
//!
//! Both halves live in one module so the tests exercise the same code the enclave and the client
//! each run, rather than a test-only reimplementation of one side.
//!
//! # Relationship to RFC 9458 §4.4
//!
//! Followed as written. The one substitution is [`RESPONSE_EXPORTER_LABEL`] in place of `"message/bhttp response"`.
//! §4.4 step 1 points at §4.6, *Repurposing the Encapsulation Format*, for alternative message
//! formats, and §6.4, *Key Management*, adds that the label was chosen for symmetry only and that
//! designers reusing the format should pick a different one for key diversity. We carry no BHTTP,
//! so this is a substitution the RFC directs rather than a deviation from it.

use aes_gcm::{
    Aes256Gcm, Key, KeyInit,
    aead::{Aead, Nonce},
};
use hkdf::Hkdf;
use hpke::rand_core::CryptoRng;
pub use hpke::rand_core::UnwrapErr;
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, aead::AeadCtxS,
    setup_receiver, setup_sender_with_rng,
};
use sha2::Sha256;
use zeroize::Zeroizing;

/// The channel ciphersuite, pinned at the type level so it cannot drift silently:
/// DHKEM(X25519, HKDF-SHA256) — RFC 9180 §7.1.
type Kem = hpke::kem::X25519HkdfSha256;
/// HKDF-SHA256 — RFC 9180 §7.2.
type Kdf = hpke::kdf::HkdfSha256;
/// AES-256-GCM — RFC 9180 §7.3, AEAD id `0x0002`.
type ChannelAead = hpke::aead::AesGcm256;

/// Version of the match channel's wire contract.
///
/// Bound into the HPKE `info` (see [`channel_info`]) and repeated inside the sealed request
/// plaintext, so a version change fails at channel setup rather than as a misparse.
pub const CHANNEL_VERSION: u8 = 1;

/// Length of an X25519 public key, which is what the enclave attests.
pub const ENCRYPTION_KEY_LEN: usize = 32;

/// Domain-separation prefix for the channel's HPKE `info`.
const CHANNEL_INFO_DOMAIN: &[u8] = b"embedding-verifier/match";

/// Exporter context for the response secret — RFC 9458 §4.4 step 1. Substituted for the RFC's `"message/bhttp response"` under §4.6 and §4.4
const RESPONSE_EXPORTER_LABEL: &[u8] = b"embedding-verifier/match response";

/// `Expand` info for the response AEAD key — RFC 9458 §4.4 step 4.
const INFO_KEY: &[u8] = b"key";

/// `Expand` info for the response AEAD nonce — RFC 9458 §4.4 step 5.
const INFO_NONCE: &[u8] = b"nonce";

/// Length of an HPKE encapsulated key under DHKEM(X25519, HKDF-SHA256) — RFC 9180 §7.1.
const ENCAPSULATED_KEY_LEN: usize = 32;

/// AES-256-GCM key length — RFC 9180 §7.3 `Nk`.
const AEAD_KEY_LEN: usize = 32;

/// AES-256-GCM nonce length — RFC 9180 §7.3 `Nn`.
const AEAD_NONCE_LEN: usize = 12;

/// GCM authentication tag length — RFC 9180 §7.3 `Nt`.
const AEAD_TAG_LEN: usize = 16;

/// `max(Nn, Nk)`, the length RFC 9458 §4.4 uses for both the exported secret (step 1) and the
/// `response_nonce` (step 2).
const RESPONSE_NONCE_LEN: usize = if AEAD_NONCE_LEN > AEAD_KEY_LEN {
    AEAD_NONCE_LEN
} else {
    AEAD_KEY_LEN
};

const _: () = assert!(RESPONSE_NONCE_LEN >= AEAD_KEY_LEN);
const _: () = assert!(RESPONSE_NONCE_LEN >= AEAD_NONCE_LEN);

/// Why a channel operation did not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
    /// A wire body was too short to hold its framing, a tag, and any plaintext.
    Truncated,
    /// The encapsulated key was malformed, or yielded the all-zero shared secret that
    /// RFC 9180 §7.1.4 requires the KEM to abort on.
    InvalidEncapsulatedKey,
    /// The advertised encryption public key was not a valid X25519 point.
    InvalidEncryptionKey,
    /// The ciphertext failed authentication under the derived key.
    OpenFailed,
    /// Exporting the response secret from the request context failed — RFC 9458 §4.4 step 1.
    ExportFailed,
    /// Deriving the response AEAD key or nonce failed — RFC 9458 §4.4 steps 3 to 5.
    DeriveFailed,
    /// The AEAD refused to seal, which a well-formed key and nonce make unreachable.
    SealFailed,
}

/// A sealed request on the wire: `enc || ciphertext`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedRequest(Vec<u8>);

impl SealedRequest {
    /// Wraps request bytes. Validation happens in [`Responder::open`].
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Returns the raw wire bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for SealedRequest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A sealed response on the wire: `response_nonce || ciphertext`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedResponse(Vec<u8>);

impl SealedResponse {
    /// Wraps response bytes. Validation happens in [`ResponseOpener::open`].
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Returns the raw wire bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for SealedResponse {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

fn channel_info(version: u8, encryption_public_key: &[u8; ENCRYPTION_KEY_LEN]) -> Vec<u8> {
    let mut info = Vec::with_capacity(CHANNEL_INFO_DOMAIN.len() + 1 + encryption_public_key.len());
    info.extend_from_slice(CHANNEL_INFO_DOMAIN);
    info.push(version);
    info.extend_from_slice(encryption_public_key);
    info
}

type ResponseSecret = Zeroizing<[u8; RESPONSE_NONCE_LEN]>;

fn derive_response_aead(
    secret: &ResponseSecret,
    encapsulated_key: &[u8; ENCAPSULATED_KEY_LEN],
    response_nonce: &[u8; RESPONSE_NONCE_LEN],
) -> Result<(Aes256Gcm, Nonce<Aes256Gcm>), ChannelError> {
    let mut salt = Vec::with_capacity(ENCAPSULATED_KEY_LEN + RESPONSE_NONCE_LEN);
    salt.extend_from_slice(encapsulated_key);
    salt.extend_from_slice(response_nonce);

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), secret.as_slice());

    let mut key = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    let mut nonce = Zeroizing::new([0u8; AEAD_NONCE_LEN]);
    hkdf.expand(INFO_KEY, key.as_mut_slice())
        .and_then(|()| hkdf.expand(INFO_NONCE, nonce.as_mut_slice()))
        .map_err(|_| ChannelError::DeriveFailed)?;

    Ok((
        Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key)),
        Nonce::<Aes256Gcm>::from(*nonce),
    ))
}

/// Responder-side boot keypair. Opens sealed requests and seals responses.
pub struct Responder {
    secret_key: <Kem as KemTrait>::PrivateKey,
    public_key: [u8; ENCRYPTION_KEY_LEN],
}

impl Responder {
    /// Generates a fresh keypair from `rng`.
    ///
    /// # Panics
    ///
    /// Panics if the KEM produces a public key that is not [`ENCRYPTION_KEY_LEN`] bytes.
    #[must_use]
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        let (secret_key, public_key) = Kem::gen_keypair_with_rng(rng);
        let public_key = public_key
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("X25519 public keys are 32 bytes");

        Self {
            secret_key,
            public_key,
        }
    }

    /// Returns the public key requesters seal to for this boot.
    #[must_use]
    pub const fn public_key(&self) -> [u8; ENCRYPTION_KEY_LEN] {
        self.public_key
    }

    /// Opens a sealed request and returns the plaintext plus a [`ResponseSealer`] for the reply.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError`] if the request is too short, the encapsulated key is unusable, the
    /// ciphertext fails authentication, or the response secret cannot be exported.
    pub fn open(
        &self,
        request: &SealedRequest,
    ) -> Result<(Zeroizing<Vec<u8>>, ResponseSealer), ChannelError> {
        let body = request.as_ref();
        if body.len() <= ENCAPSULATED_KEY_LEN + AEAD_TAG_LEN {
            return Err(ChannelError::Truncated);
        }
        let (encapsulated, ciphertext) = body.split_at(ENCAPSULATED_KEY_LEN);
        let encapsulated_key: [u8; ENCAPSULATED_KEY_LEN] = encapsulated
            .try_into()
            .map_err(|_| ChannelError::Truncated)?;

        let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(encapsulated)
            .map_err(|_| ChannelError::InvalidEncapsulatedKey)?;

        let info = channel_info(CHANNEL_VERSION, &self.public_key);
        let mut context = setup_receiver::<ChannelAead, Kdf, Kem>(
            &OpModeR::Base,
            &self.secret_key,
            &encapped,
            &info,
        )
        .map_err(|_| ChannelError::InvalidEncapsulatedKey)?;

        let plaintext = context
            .open(ciphertext, &[])
            .map_err(|_| ChannelError::OpenFailed)?;

        let mut secret = Zeroizing::new([0u8; RESPONSE_NONCE_LEN]);
        context
            .export(RESPONSE_EXPORTER_LABEL, secret.as_mut_slice())
            .map_err(|_| ChannelError::ExportFailed)?;

        Ok((
            Zeroizing::new(plaintext),
            ResponseSealer {
                secret,
                encapsulated_key,
            },
        ))
    }
}

/// Requester-side handle built from a verified encryption public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Requester {
    public_key: [u8; ENCRYPTION_KEY_LEN],
}

impl Requester {
    /// Builds a requester from an attested encryption public key.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::InvalidEncryptionKey`] if `public_key` is not a valid X25519 point.
    pub fn new(public_key: [u8; ENCRYPTION_KEY_LEN]) -> Result<Self, ChannelError> {
        <Kem as KemTrait>::PublicKey::from_bytes(&public_key)
            .map_err(|_| ChannelError::InvalidEncryptionKey)?;
        Ok(Self { public_key })
    }

    /// Builds a requester from attestation document bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::InvalidEncryptionKey`] if `public_key` is not exactly
    /// [`ENCRYPTION_KEY_LEN`] bytes or not a valid X25519 point.
    pub fn from_attestation(public_key: &[u8]) -> Result<Self, ChannelError> {
        let public_key: [u8; ENCRYPTION_KEY_LEN] = public_key
            .try_into()
            .map_err(|_| ChannelError::InvalidEncryptionKey)?;
        Self::new(public_key)
    }

    /// Returns the raw X25519 public key.
    #[must_use]
    pub const fn public_key(&self) -> [u8; ENCRYPTION_KEY_LEN] {
        self.public_key
    }

    /// Seals one request, returning the wire body and a [`ResponseOpener`] for the reply.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError`] if the AEAD refuses to seal.
    pub fn seal(
        &self,
        plaintext: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<(SealedRequest, ResponseOpener), ChannelError> {
        self.seal_with_version(CHANNEL_VERSION, plaintext, rng)
    }

    fn seal_with_version(
        &self,
        version: u8,
        plaintext: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<(SealedRequest, ResponseOpener), ChannelError> {
        let public_key = <Kem as KemTrait>::PublicKey::from_bytes(&self.public_key)
            .map_err(|_| ChannelError::InvalidEncryptionKey)?;

        let info = channel_info(version, &self.public_key);
        let (encapped, mut context) =
            setup_sender_with_rng::<ChannelAead, Kdf, Kem>(&OpModeS::Base, &public_key, &info, rng)
                .map_err(|_| ChannelError::InvalidEncryptionKey)?;

        let ciphertext = context
            .seal(plaintext, &[])
            .map_err(|_| ChannelError::SealFailed)?;

        let encapsulated = encapped.to_bytes();
        let encapsulated_key: [u8; ENCAPSULATED_KEY_LEN] = encapsulated
            .as_slice()
            .try_into()
            .map_err(|_| ChannelError::InvalidEncapsulatedKey)?;

        let mut body = encapsulated_key.to_vec();
        body.extend_from_slice(&ciphertext);

        Ok((
            SealedRequest(body),
            ResponseOpener {
                context,
                encapsulated_key,
            },
        ))
    }
}

/// Opens the response belonging to one [`Requester::seal`] call.
pub struct ResponseOpener {
    context: AeadCtxS<ChannelAead, Kdf, Kem>,
    encapsulated_key: [u8; ENCAPSULATED_KEY_LEN],
}

impl ResponseOpener {
    /// Opens a sealed response.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError`] if the response is too short, the secret cannot be exported or
    /// expanded, or the ciphertext fails authentication.
    pub fn open(&self, response: &SealedResponse) -> Result<Zeroizing<Vec<u8>>, ChannelError> {
        let sealed = response.as_ref();
        if sealed.len() <= RESPONSE_NONCE_LEN + AEAD_TAG_LEN {
            return Err(ChannelError::Truncated);
        }
        let (response_nonce, ciphertext) = sealed.split_at(RESPONSE_NONCE_LEN);
        let response_nonce: [u8; RESPONSE_NONCE_LEN] = response_nonce
            .try_into()
            .map_err(|_| ChannelError::Truncated)?;

        let mut secret = Zeroizing::new([0u8; RESPONSE_NONCE_LEN]);
        self.context
            .export(RESPONSE_EXPORTER_LABEL, secret.as_mut_slice())
            .map_err(|_| ChannelError::ExportFailed)?;

        let (cipher, nonce) =
            derive_response_aead(&secret, &self.encapsulated_key, &response_nonce)?;

        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| ChannelError::OpenFailed)?;

        Ok(Zeroizing::new(plaintext))
    }
}

/// Seals the one response belonging to a [`Responder::open`] call.
pub struct ResponseSealer {
    secret: ResponseSecret,
    encapsulated_key: [u8; ENCAPSULATED_KEY_LEN],
}

impl ResponseSealer {
    /// Seals one response, per RFC 9458 §4.4.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError`] if the key or nonce cannot be expanded, or the AEAD refuses to
    /// seal.
    pub fn seal(
        self,
        plaintext: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<SealedResponse, ChannelError> {
        let mut response_nonce = [0u8; RESPONSE_NONCE_LEN];
        rng.fill_bytes(&mut response_nonce);

        let (cipher, nonce) =
            derive_response_aead(&self.secret, &self.encapsulated_key, &response_nonce)?;

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| ChannelError::SealFailed)?;

        let mut sealed = response_nonce.to_vec();
        sealed.extend_from_slice(&ciphertext);

        Ok(SealedResponse(sealed))
    }
}

#[cfg(test)]
mod tests {
    use getrandom::SysRng;
    use hpke::rand_core::UnwrapErr;

    use super::{
        AEAD_TAG_LEN, CHANNEL_INFO_DOMAIN, CHANNEL_VERSION, ChannelError, ENCAPSULATED_KEY_LEN,
        RESPONSE_NONCE_LEN, Requester, Responder, ResponseOpener, SealedRequest, SealedResponse,
        channel_info,
    };

    fn seal_to(responder: &Responder, plaintext: &[u8]) -> (SealedRequest, ResponseOpener) {
        let requester = Requester::new(responder.public_key()).expect("valid key");
        let mut rng = UnwrapErr(SysRng);
        let (request, opener) = requester
            .seal(plaintext, &mut rng)
            .expect("sealing should succeed");
        (request, opener)
    }

    fn test_rng() -> UnwrapErr<SysRng> {
        UnwrapErr(SysRng)
    }

    #[test]
    fn requester_from_attestation_matches_new() {
        let responder = Responder::generate(&mut test_rng());
        let from_attestation =
            Requester::from_attestation(&responder.public_key()).expect("should parse");
        let from_new = Requester::new(responder.public_key()).expect("should parse");
        assert_eq!(from_attestation, from_new);
    }

    #[test]
    fn rejects_a_non_32_byte_attestation_key() {
        assert_eq!(
            Requester::from_attestation(&[0u8; 31]).err(),
            Some(ChannelError::InvalidEncryptionKey)
        );
    }

    #[test]
    fn channel_info_binds_domain_version_and_key() {
        let key = [7u8; 32];
        let info = channel_info(CHANNEL_VERSION, &key);
        let (domain, rest) = info.split_at(CHANNEL_INFO_DOMAIN.len());
        assert_eq!(domain, CHANNEL_INFO_DOMAIN);
        assert_eq!(rest, [&[CHANNEL_VERSION][..], &key[..]].concat());
    }

    #[test]
    fn channel_info_separates_versions_and_keys() {
        let key = [7u8; 32];
        assert_ne!(channel_info(1, &key), channel_info(2, &key));
        assert_ne!(channel_info(1, &key), channel_info(1, &[8u8; 32]));
    }

    #[test]
    fn separate_responders_receive_separate_public_keys() {
        assert_ne!(
            Responder::generate(&mut test_rng()).public_key(),
            Responder::generate(&mut test_rng()).public_key()
        );
    }

    #[test]
    fn public_key_is_stable_for_one_responder() {
        let responder = Responder::generate(&mut test_rng());
        assert_eq!(responder.public_key(), responder.public_key());
    }

    #[test]
    fn round_trips_a_request_and_its_sealed_response() {
        let responder = Responder::generate(&mut test_rng());
        let (request, opener) = seal_to(&responder, b"match inputs");

        let (plaintext, sealer) = responder.open(&request).expect("should open");
        assert_eq!(&plaintext[..], b"match inputs");

        let response = sealer
            .seal(b"statement", &mut test_rng())
            .expect("sealing should succeed");

        assert_eq!(&*opener.open(&response).unwrap(), b"statement".as_ref());
    }

    #[test]
    fn each_response_draws_a_fresh_nonce() {
        let responder = Responder::generate(&mut test_rng());
        let (request, opener) = seal_to(&responder, b"match inputs");

        let (_, first_sealer) = responder.open(&request).expect("should open");
        let (_, second_sealer) = responder.open(&request).expect("should open");
        let first = first_sealer
            .seal(b"statement", &mut test_rng())
            .expect("should seal");
        let second = second_sealer
            .seal(b"statement", &mut test_rng())
            .expect("should seal");

        assert_ne!(
            first.as_ref()[..RESPONSE_NONCE_LEN],
            second.as_ref()[..RESPONSE_NONCE_LEN],
        );
        assert_ne!(
            first.as_ref()[RESPONSE_NONCE_LEN..],
            second.as_ref()[RESPONSE_NONCE_LEN..],
        );
        assert_eq!(&*opener.open(&first).unwrap(), b"statement".as_ref());
        assert_eq!(&*opener.open(&second).unwrap(), b"statement".as_ref());
    }

    #[test]
    fn rejects_a_request_sealed_to_another_boot() {
        let responder = Responder::generate(&mut test_rng());
        let other = Responder::generate(&mut test_rng());
        let (request, _) = seal_to(&other, b"match inputs");

        assert_eq!(
            responder.open(&request).err(),
            Some(ChannelError::OpenFailed)
        );
    }

    #[test]
    fn rejects_a_request_bound_to_another_channel_version() {
        let responder = Responder::generate(&mut test_rng());
        let requester = Requester::new(responder.public_key()).expect("valid key");
        let (request, _) = requester
            .seal_with_version(CHANNEL_VERSION + 1, b"match inputs", &mut test_rng())
            .expect("sealing should succeed");

        assert_eq!(
            responder.open(&request).err(),
            Some(ChannelError::OpenFailed)
        );
    }

    #[test]
    fn rejects_a_low_order_encapsulated_key() {
        let responder = Responder::generate(&mut test_rng());
        let (request, _) = seal_to(&responder, b"match inputs");
        let mut body = request.into_bytes();
        body[..ENCAPSULATED_KEY_LEN].fill(0);

        assert_eq!(
            responder.open(&SealedRequest(body)).err(),
            Some(ChannelError::InvalidEncapsulatedKey)
        );
    }

    #[test]
    fn rejects_a_truncated_request_body() {
        let responder = Responder::generate(&mut test_rng());

        for length in [0, ENCAPSULATED_KEY_LEN, ENCAPSULATED_KEY_LEN + AEAD_TAG_LEN] {
            assert_eq!(
                responder
                    .open(&SealedRequest::from_bytes(vec![0u8; length]))
                    .err(),
                Some(ChannelError::Truncated),
                "length {length}"
            );
        }
    }

    #[test]
    fn rejects_a_tampered_request_ciphertext() {
        let responder = Responder::generate(&mut test_rng());
        let (request, _) = seal_to(&responder, b"match inputs");
        let mut body = request.into_bytes();
        body[ENCAPSULATED_KEY_LEN] ^= 0x01;

        assert_eq!(
            responder.open(&SealedRequest(body)).err(),
            Some(ChannelError::OpenFailed)
        );
    }

    #[test]
    fn rejects_a_truncated_response() {
        let responder = Responder::generate(&mut test_rng());

        for length in [0, RESPONSE_NONCE_LEN, RESPONSE_NONCE_LEN + AEAD_TAG_LEN] {
            let (_, opener) = seal_to(&responder, b"match inputs");
            assert_eq!(
                opener
                    .open(&SealedResponse::from_bytes(vec![0u8; length]))
                    .err(),
                Some(ChannelError::Truncated),
                "length {length}"
            );
        }
    }

    #[test]
    fn a_second_request_to_the_same_key_cannot_open_the_response() {
        let responder = Responder::generate(&mut test_rng());
        let (request, _) = seal_to(&responder, b"match inputs");
        let (_, eavesdropper) = seal_to(&responder, b"unrelated");

        let (_, sealer) = responder.open(&request).expect("should open");
        let response = sealer
            .seal(b"statement", &mut test_rng())
            .expect("sealing should succeed");

        assert_eq!(
            eavesdropper.open(&response).err(),
            Some(ChannelError::OpenFailed)
        );
    }

    #[test]
    fn rejects_a_tampered_response_ciphertext() {
        let responder = Responder::generate(&mut test_rng());
        let (request, opener) = seal_to(&responder, b"match inputs");
        let (_, sealer) = responder.open(&request).expect("should open");

        let response = sealer
            .seal(b"statement", &mut test_rng())
            .expect("sealing should succeed");
        let mut body = response.into_bytes();
        body[RESPONSE_NONCE_LEN] ^= 0x01;

        assert_eq!(
            opener.open(&SealedResponse(body)).err(),
            Some(ChannelError::OpenFailed)
        );
    }

    #[test]
    fn rejects_a_tampered_response_nonce() {
        let responder = Responder::generate(&mut test_rng());
        let (request, opener) = seal_to(&responder, b"match inputs");
        let (_, sealer) = responder.open(&request).expect("should open");

        let response = sealer
            .seal(b"statement", &mut test_rng())
            .expect("sealing should succeed");
        let mut body = response.into_bytes();
        body[0] ^= 0x01;

        assert_eq!(
            opener.open(&SealedResponse(body)).err(),
            Some(ChannelError::OpenFailed)
        );
    }

    #[test]
    fn rejects_an_invalid_encryption_key() {
        // All-zero encodes as a point but yields no valid shared secret at encapsulation.
        let requester = Requester::new([0u8; 32]).expect("all-zero key encodes");
        let result = requester.seal(b"match inputs", &mut test_rng());

        assert_eq!(result.err(), Some(ChannelError::InvalidEncryptionKey));
    }
}

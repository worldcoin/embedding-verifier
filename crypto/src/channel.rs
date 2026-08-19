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
//! # Deviations from RFC 9458 §4.4
//!
//! Two, both deliberate:
//!
//! - **Exporter label.** §4.4 step 1 uses `"message/bhttp response"` and points at §4.6,
//!   *Repurposing the Encapsulation Format*, for alternative message formats. §6.4, *Key
//!   Management*, adds that the label was chosen for symmetry only and that designers reusing the
//!   format should pick a different one for key diversity. We carry no BHTTP, so we substitute
//!   [`RESPONSE_EXPORTER_LABEL`] — a deviation the RFC asks for rather than tolerates.
//! - **Non-empty AAD.** §4.4 step 6 seals with an empty `aad`. We bind a caller-supplied `aad`,
//!   so a cleartext field travelling beside the ciphertext cannot be rewritten by the untrusted
//!   host without breaking authentication. OHTTP has no such field to protect.
//!
//! Everything else — the exported secret length, the fresh `response_nonce`, the
//! `enc || response_nonce` salt, the `Extract`/`Expand` labels, and the
//! `response_nonce || ciphertext` wire layout — follows §4.4 as written.

use aes_gcm::{
    Aes256Gcm, Key, KeyInit,
    aead::{Aead, Nonce, Payload},
};
use hkdf::Hkdf;
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, aead::AeadCtxS,
    setup_receiver, setup_sender,
};
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use zeroize::Zeroizing;

/// The channel ciphersuite, pinned at the type level so it cannot drift silently:
/// DHKEM(X25519, HKDF-SHA256) — RFC 9180 §7.1.
type Kem = hpke::kem::X25519HkdfSha256;
/// HKDF-SHA256 — RFC 9180 §7.2.
type Kdf = hpke::kdf::HkdfSha256;
/// AES-256-GCM — RFC 9180 §7.3, AEAD id `0x0002`.
///
/// Chosen for uniformity, not strength: 128-bit would already be beyond brute force for a
/// single-use per-request key, and the confidentiality ceiling here is X25519, which a larger
/// AEAD key does nothing for. What it buys is one AEAD and one key length across the channel,
/// the response half, and challenge images — whose format the RP fixes at AES-256-GCM.
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

/// Exporter context for the response secret — RFC 9458 §4.4 step 1.
///
/// Substituted for the RFC's `"message/bhttp response"` under §4.6 and §6.4, which direct anyone
/// reusing the format to choose their own label for key diversity. Changing this value changes the
/// response key, so it is part of the wire contract and moves only with [`CHANNEL_VERSION`].
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
///
/// Computed rather than written out so it cannot drift if the suite changes.
const RESPONSE_NONCE_LEN: usize = if AEAD_NONCE_LEN > AEAD_KEY_LEN {
    AEAD_NONCE_LEN
} else {
    AEAD_KEY_LEN
};

// The exported secret is used as HKDF input keying material and the response nonce is the HKDF
// salt suffix, so both must cover the wider of the two AEAD parameters. Checked at compile time
// rather than in a test, so changing the suite cannot slip past.
const _: () = assert!(RESPONSE_NONCE_LEN >= AEAD_KEY_LEN);
const _: () = assert!(RESPONSE_NONCE_LEN >= AEAD_NONCE_LEN);

/// Why a channel operation did not complete.
///
/// Callers facing an untrusted peer are expected to collapse these into one opaque rejection;
/// the distinctions exist so the enclave log can say which stage failed.
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

/// Builds the HPKE `info` both parties bind into the key schedule.
///
/// Binding the encryption key means a client that sealed to a *different* enclave boot cannot
/// open a channel at all; binding `version` means a wire-format change fails at setup rather
/// than producing a garbled plaintext.
fn channel_info(version: u8, encryption_public_key: &[u8; ENCRYPTION_KEY_LEN]) -> Vec<u8> {
    let mut info = Vec::with_capacity(CHANNEL_INFO_DOMAIN.len() + 1 + encryption_public_key.len());
    info.extend_from_slice(CHANNEL_INFO_DOMAIN);
    info.push(version);
    info.extend_from_slice(encryption_public_key);
    info
}

/// Response secret exported from a request context — RFC 9458 §4.4 step 1.
type ResponseSecret = Zeroizing<[u8; RESPONSE_NONCE_LEN]>;

/// Derives the response AEAD from the exported secret — RFC 9458 §4.4 steps 3 to 5.
///
/// Step 3 extracts `prk` with `ikm = secret` and `salt = enc || response_nonce`; steps 4 and 5
/// expand it under [`INFO_KEY`] and [`INFO_NONCE`]. Mixing a fresh `response_nonce` in is what
/// gives every response a unique key and nonce — the property §6.5, *Replay Attacks*, relies on
/// to stay sound even when a request is replayed.
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

/// The enclave's side of the channel: a boot-scoped X25519 keypair.
///
/// The public key is what travels in the `public_key` field of the enclave's attestation
/// document, so a client only ever seals to a key it has verified.
pub struct ChannelKeypair {
    secret_key: <Kem as KemTrait>::PrivateKey,
    public_key: [u8; ENCRYPTION_KEY_LEN],
}

impl ChannelKeypair {
    /// Generates a fresh keypair from the system RNG.
    ///
    /// Inside an enclave the system RNG is the Nitro hardware RNG, which the boot sequence
    /// verifies before this is reached. `hpke` panics rather than returning if the RNG fails,
    /// which is the correct hard gate for key generation.
    ///
    /// # Panics
    ///
    /// Panics if the KEM produces a public key that is not [`ENCRYPTION_KEY_LEN`] bytes, which
    /// the DHKEM(X25519, HKDF-SHA256) definition makes impossible.
    #[must_use]
    pub fn generate() -> Self {
        let (secret_key, public_key) = Kem::gen_keypair();
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

    /// Returns the public key clients seal to for this boot.
    #[must_use]
    pub const fn public_key(&self) -> [u8; ENCRYPTION_KEY_LEN] {
        self.public_key
    }

    /// Opens a request sealed to this boot's public key.
    ///
    /// Splits the wire body into the fixed-width encapsulated key and the ciphertext, runs
    /// `SetupBaseR` (RFC 9180 §5.1.1), and opens. Base mode means the sender is anonymous by
    /// design: callers are not pre-registered, and provenance is enforced downstream.
    ///
    /// Returns the plaintext together with a [`ResponseSealer`] carrying the secret exported
    /// from the *same* context, which is what makes the reply readable only by this request's
    /// sender.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError`] if the body is too short, the encapsulated key is unusable, the
    /// ciphertext fails authentication, or the response secret cannot be exported. No plaintext,
    /// ciphertext, or key material is surfaced in the error.
    pub fn open_request(&self, body: &[u8]) -> Result<(Vec<u8>, ResponseSealer), ChannelError> {
        // A well-formed body carries an encapsulated key, at least one plaintext byte, and a
        // tag, so anything at or below the fixed overhead cannot be valid.
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

        // Nothing outside the ciphertext needs binding as AAD: `enc` is already folded into the
        // key schedule by the KEM, and the request carries no other cleartext field.
        let plaintext = context
            .open(ciphertext, &[])
            .map_err(|_| ChannelError::OpenFailed)?;

        let mut secret = Zeroizing::new([0u8; RESPONSE_NONCE_LEN]);
        context
            .export(RESPONSE_EXPORTER_LABEL, secret.as_mut_slice())
            .map_err(|_| ChannelError::ExportFailed)?;

        Ok((
            plaintext,
            ResponseSealer {
                secret,
                encapsulated_key,
            },
        ))
    }
}

/// The client's side of one channel, held across the request so the response can be opened.
pub struct RequestChannel {
    context: AeadCtxS<ChannelAead, Kdf, Kem>,
    encapsulated_key: [u8; ENCAPSULATED_KEY_LEN],
}

impl RequestChannel {
    /// Runs `SetupBaseS` against an enclave's attested encryption key and seals `plaintext`.
    ///
    /// Returns the channel plus the wire body, which is `enc || ciphertext`.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError`] if the key is not a valid X25519 point or the AEAD refuses to
    /// seal.
    pub fn seal(
        encryption_public_key: &[u8; ENCRYPTION_KEY_LEN],
        plaintext: &[u8],
    ) -> Result<(Self, Vec<u8>), ChannelError> {
        Self::seal_with_version(encryption_public_key, CHANNEL_VERSION, plaintext)
    }

    /// As [`Self::seal`], but with a caller-chosen version so tests can prove the `info`
    /// binding actually bites.
    fn seal_with_version(
        encryption_public_key: &[u8; ENCRYPTION_KEY_LEN],
        version: u8,
        plaintext: &[u8],
    ) -> Result<(Self, Vec<u8>), ChannelError> {
        let public_key = <Kem as KemTrait>::PublicKey::from_bytes(encryption_public_key)
            .map_err(|_| ChannelError::InvalidEncryptionKey)?;

        let info = channel_info(version, encryption_public_key);
        let (encapped, mut context) =
            setup_sender::<ChannelAead, Kdf, Kem>(&OpModeS::Base, &public_key, &info)
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
            Self {
                context,
                encapsulated_key,
            },
            body,
        ))
    }

    /// Opens a response sealed to this channel, binding `aad`.
    ///
    /// Parses `response_nonce || ciphertext` and re-derives the AEAD the enclave used, per
    /// RFC 9458 §4.4's client-side procedure.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError`] if the response is too short, the secret cannot be exported or
    /// expanded, or the ciphertext fails authentication under the derived key — which is also
    /// what a rewritten `aad` or a tampered `response_nonce` looks like.
    pub fn open_response(&self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, ChannelError> {
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

        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| ChannelError::OpenFailed)
    }
}

/// Seals the one response belonging to a request, per RFC 9458 §4.4.
pub struct ResponseSealer {
    secret: ResponseSecret,
    encapsulated_key: [u8; ENCAPSULATED_KEY_LEN],
}

impl ResponseSealer {
    /// Seals `plaintext` binding `aad`, returning `response_nonce || ciphertext`.
    ///
    /// Follows RFC 9458 §4.4 steps 2 to 7: a fresh `response_nonce` is drawn per response and
    /// mixed into the key schedule, so the AEAD key and nonce are unique per response rather
    /// than fixed for the lifetime of the context.
    ///
    /// Consumes `self` because the protocol has exactly one response per request. Unlike a
    /// construction that exported the nonce directly, this is a protocol constraint and not a
    /// nonce-reuse guard — the fresh nonce of step 2 makes a second seal safe on its own, which
    /// is what §6.5 depends on.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError`] if the key or nonce cannot be expanded, or the AEAD refuses to
    /// seal — which a well-formed key, nonce, and in-memory plaintext make unreachable.
    pub fn seal(self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, ChannelError> {
        // Step 2. Inside the enclave this is the Nitro hardware RNG.
        let mut response_nonce = [0u8; RESPONSE_NONCE_LEN];
        OsRng.fill_bytes(&mut response_nonce);

        let (cipher, nonce) =
            derive_response_aead(&self.secret, &self.encapsulated_key, &response_nonce)?;

        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| ChannelError::SealFailed)?;

        // Step 7. `response_nonce` is fixed-length, so parsing is unambiguous.
        let mut sealed = response_nonce.to_vec();
        sealed.extend_from_slice(&ciphertext);

        Ok(sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AEAD_TAG_LEN, CHANNEL_INFO_DOMAIN, CHANNEL_VERSION, ChannelError, ChannelKeypair,
        ENCAPSULATED_KEY_LEN, RESPONSE_NONCE_LEN, RequestChannel, channel_info,
    };

    const AAD: &[u8] = b"\x01";

    /// Seals `plaintext` to `keypair` and returns the client channel plus the wire body.
    fn sealed_to(keypair: &ChannelKeypair, plaintext: &[u8]) -> (RequestChannel, Vec<u8>) {
        RequestChannel::seal(&keypair.public_key(), plaintext).expect("sealing should succeed")
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
    fn separate_keypairs_receive_separate_public_keys() {
        assert_ne!(
            ChannelKeypair::generate().public_key(),
            ChannelKeypair::generate().public_key()
        );
    }

    #[test]
    fn public_key_is_stable_for_one_keypair() {
        let keypair = ChannelKeypair::generate();

        assert_eq!(keypair.public_key(), keypair.public_key());
    }

    #[test]
    fn round_trips_a_request_and_its_sealed_response() {
        let keypair = ChannelKeypair::generate();
        let (client, body) = sealed_to(&keypair, b"match inputs");

        let (plaintext, sealer) = keypair
            .open_request(&body)
            .expect("a well-formed request should open");
        assert_eq!(plaintext, b"match inputs");

        let response = sealer
            .seal(b"statement", AAD)
            .expect("sealing should succeed");

        assert_eq!(
            client.open_response(&response, AAD).as_deref(),
            Ok(&b"statement"[..])
        );
    }

    #[test]
    fn each_response_draws_a_fresh_nonce() {
        // The property §4.4 relies on: two responses derived from the *same* context still get
        // distinct AEAD keys and nonces, so a replayed request cannot force nonce reuse.
        let keypair = ChannelKeypair::generate();
        let (client, body) = sealed_to(&keypair, b"match inputs");

        let (_, first_sealer) = keypair.open_request(&body).expect("should open");
        let (_, second_sealer) = keypair.open_request(&body).expect("should open");
        let first = first_sealer.seal(b"statement", AAD).expect("should seal");
        let second = second_sealer.seal(b"statement", AAD).expect("should seal");

        assert_ne!(
            first[..RESPONSE_NONCE_LEN],
            second[..RESPONSE_NONCE_LEN],
            "response nonces must not repeat"
        );
        // Both remain openable, and the same plaintext yields different ciphertext.
        assert_ne!(first[RESPONSE_NONCE_LEN..], second[RESPONSE_NONCE_LEN..]);
        assert_eq!(
            client.open_response(&first, AAD).as_deref(),
            Ok(&b"statement"[..])
        );
        assert_eq!(
            client.open_response(&second, AAD).as_deref(),
            Ok(&b"statement"[..])
        );
    }

    #[test]
    fn rejects_a_request_sealed_to_another_boot() {
        let keypair = ChannelKeypair::generate();
        let other = ChannelKeypair::generate();
        let (_, body) = sealed_to(&other, b"match inputs");

        assert_eq!(
            keypair.open_request(&body).err(),
            Some(ChannelError::OpenFailed)
        );
    }

    #[test]
    fn rejects_a_request_bound_to_another_channel_version() {
        let keypair = ChannelKeypair::generate();
        let public_key = keypair.public_key();
        let (_, body) =
            RequestChannel::seal_with_version(&public_key, CHANNEL_VERSION + 1, b"match inputs")
                .expect("sealing should succeed");

        assert_eq!(
            keypair.open_request(&body).err(),
            Some(ChannelError::OpenFailed)
        );
    }

    #[test]
    fn rejects_a_low_order_encapsulated_key() {
        // RFC 9180 §7.1.4: an all-zero X25519 shared secret must abort.
        let keypair = ChannelKeypair::generate();
        let (_, mut body) = sealed_to(&keypair, b"match inputs");
        body[..ENCAPSULATED_KEY_LEN].fill(0);

        assert_eq!(
            keypair.open_request(&body).err(),
            Some(ChannelError::InvalidEncapsulatedKey)
        );
    }

    #[test]
    fn rejects_a_truncated_request_body() {
        let keypair = ChannelKeypair::generate();

        for length in [0, ENCAPSULATED_KEY_LEN, ENCAPSULATED_KEY_LEN + AEAD_TAG_LEN] {
            assert_eq!(
                keypair.open_request(&vec![0u8; length]).err(),
                Some(ChannelError::Truncated),
                "length {length}"
            );
        }
    }

    #[test]
    fn rejects_a_tampered_request_ciphertext() {
        let keypair = ChannelKeypair::generate();
        let (_, mut body) = sealed_to(&keypair, b"match inputs");
        body[ENCAPSULATED_KEY_LEN] ^= 0x01;

        assert_eq!(
            keypair.open_request(&body).err(),
            Some(ChannelError::OpenFailed)
        );
    }

    #[test]
    fn rejects_a_truncated_response() {
        let keypair = ChannelKeypair::generate();
        let (client, _) = sealed_to(&keypair, b"match inputs");

        for length in [0, RESPONSE_NONCE_LEN, RESPONSE_NONCE_LEN + AEAD_TAG_LEN] {
            assert_eq!(
                client.open_response(&vec![0u8; length], AAD).err(),
                Some(ChannelError::Truncated),
                "length {length}"
            );
        }
    }

    #[test]
    fn a_second_channel_to_the_same_key_cannot_open_the_response() {
        let keypair = ChannelKeypair::generate();
        let (_, body) = sealed_to(&keypair, b"match inputs");
        // A second setup against the same key: a different ephemeral, so a different exporter
        // secret.
        let (eavesdropper, _) = sealed_to(&keypair, b"unrelated");

        let (_, sealer) = keypair.open_request(&body).expect("should open");
        let response = sealer
            .seal(b"statement", AAD)
            .expect("sealing should succeed");

        assert_eq!(
            eavesdropper.open_response(&response, AAD).err(),
            Some(ChannelError::OpenFailed)
        );
    }

    #[test]
    fn rejects_a_tampered_response_ciphertext() {
        let keypair = ChannelKeypair::generate();
        let (client, body) = sealed_to(&keypair, b"match inputs");
        let (_, sealer) = keypair.open_request(&body).expect("should open");

        let mut response = sealer
            .seal(b"statement", AAD)
            .expect("sealing should succeed");
        response[RESPONSE_NONCE_LEN] ^= 0x01;

        assert_eq!(
            client.open_response(&response, AAD).err(),
            Some(ChannelError::OpenFailed)
        );
    }

    #[test]
    fn rejects_a_tampered_response_nonce() {
        // The nonce is cleartext on the wire, but it is folded into the salt, so flipping it
        // changes the derived key and the open fails.
        let keypair = ChannelKeypair::generate();
        let (client, body) = sealed_to(&keypair, b"match inputs");
        let (_, sealer) = keypair.open_request(&body).expect("should open");

        let mut response = sealer
            .seal(b"statement", AAD)
            .expect("sealing should succeed");
        response[0] ^= 0x01;

        assert_eq!(
            client.open_response(&response, AAD).err(),
            Some(ChannelError::OpenFailed)
        );
    }

    #[test]
    fn rejects_a_rewritten_aad() {
        let keypair = ChannelKeypair::generate();
        let (client, body) = sealed_to(&keypair, b"match inputs");
        let (_, sealer) = keypair.open_request(&body).expect("should open");

        let response = sealer
            .seal(b"statement", AAD)
            .expect("sealing should succeed");

        // A host that rewrites the cleartext class the response was sealed under turns the
        // response into an authentication failure instead of a silent downgrade.
        assert_eq!(
            client.open_response(&response, b"\x02").err(),
            Some(ChannelError::OpenFailed)
        );
    }

    #[test]
    fn rejects_an_invalid_encryption_key() {
        // An all-zero X25519 public key has no valid shared secret.
        let result = RequestChannel::seal(&[0u8; 32], b"match inputs");

        assert_eq!(result.err(), Some(ChannelError::InvalidEncryptionKey));
    }
}

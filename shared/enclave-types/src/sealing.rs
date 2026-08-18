//! The HPKE contract for match payloads, in both directions.
//!
//! Everything here is a contract between the enclave and its clients, which is why it
//! lives next to the wire types rather than inside the enclave: a divergent ciphersuite,
//! `info` string, or export label on either side fails decryption with no diagnosable
//! signal. The host relays both directions opaquely and enables none of this.

use aes_gcm::{Aes128Gcm, KeyInit, aead::Aead};
use hpke::{Deserializable, OpModeR, OpModeS, Serializable, setup_receiver, setup_sender};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// DHKEM(X25519, HKDF-SHA256) — RFC 9180 §7.1.
pub type Kem = hpke::kem::X25519HkdfSha256;

/// Recipient public key for [`Kem`].
pub type PublicKey = <Kem as hpke::Kem>::PublicKey;

/// Recipient private key for [`Kem`].
pub type PrivateKey = <Kem as hpke::Kem>::PrivateKey;

/// HKDF-SHA256 — RFC 9180 §7.2.
pub type Kdf = hpke::kdf::HkdfSha256;

/// AES-128-GCM — RFC 9180 §7.3.
///
/// Chosen to match the AEAD the `WorldID` OHTTP deployment already pins, and because
/// Nitro hosts have AES-NI.
pub type Aead128 = hpke::aead::AesGcm128;

/// HPKE `info`, binding a sealed request to this service and payload version.
///
/// Changing any label in this module silently invalidates every client. Version the
/// string instead.
pub const INFO: &[u8] = b"embedding-verifier/v1/match-request";

/// Exporter label for the response key — RFC 9180 §9.8 bidirectional encryption.
const RESPONSE_KEY_LABEL: &[u8] = b"embedding-verifier/v1/match-response/key";

/// Exporter label for the response nonce.
const RESPONSE_NONCE_LABEL: &[u8] = b"embedding-verifier/v1/match-response/nonce";

/// Length of a serialized DHKEM(X25519) encapsulated key (`enc` on the wire).
pub const ENCAPPED_KEY_LEN: usize = 32;

const RESPONSE_KEY_LEN: usize = 16;
const RESPONSE_NONCE_LEN: usize = 12;

/// The symmetric key protecting one response.
///
/// Derived from the request's HPKE context by both sides, so the response needs no
/// client-held keypair. One context seals exactly one response, and every request
/// carries a fresh encapsulated key, so the exported key and nonce are never reused.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ResponseKey {
    key: [u8; RESPONSE_KEY_LEN],
    nonce: [u8; RESPONSE_NONCE_LEN],
}

impl ResponseKey {
    /// Seals a response for the client that sent the matching request.
    ///
    /// # Errors
    ///
    /// Returns an error when the AEAD rejects the plaintext.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        self.cipher().encrypt(&self.nonce.into(), plaintext)
    }

    /// Opens a response sealed against this key.
    ///
    /// # Errors
    ///
    /// Returns an error when the ciphertext fails authentication.
    pub fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        self.cipher().decrypt(&self.nonce.into(), ciphertext)
    }

    fn cipher(&self) -> Aes128Gcm {
        Aes128Gcm::new(&self.key.into())
    }
}

/// Seals a request to the enclave's attested encryption key.
///
/// Returns the framed payload and the key the enclave's response will be sealed with.
///
/// # Errors
///
/// Returns an error when encapsulation or encryption fails.
pub fn seal_request(
    encryption_public_key: &PublicKey,
    plaintext: &[u8],
) -> Result<(Vec<u8>, ResponseKey), hpke::HpkeError> {
    let (encapped_key, mut context) =
        setup_sender::<Aead128, Kdf, Kem>(&OpModeS::Base, encryption_public_key, INFO)?;
    let ciphertext = context.seal(plaintext, &[])?;
    let response_key = export_response_key(|label, out| context.export(label, out))?;

    Ok((
        frame(&encapped_key.to_bytes().into(), &ciphertext),
        response_key,
    ))
}

/// Opens a request sealed to `private_key`.
///
/// Returns the plaintext and the key the response must be sealed with.
///
/// # Errors
///
/// Returns an error when the payload is misframed, was sealed to another key, or fails
/// AEAD authentication.
pub fn open_request(
    private_key: &PrivateKey,
    sealed_payload: &[u8],
) -> Result<(Vec<u8>, ResponseKey), hpke::HpkeError> {
    let (encapped_key, ciphertext) = split(sealed_payload).ok_or(hpke::HpkeError::OpenError)?;
    let encapped_key = <Kem as hpke::Kem>::EncappedKey::from_bytes(encapped_key)?;
    let mut context =
        setup_receiver::<Aead128, Kdf, Kem>(&OpModeR::Base, private_key, &encapped_key, INFO)?;
    let plaintext = context.open(ciphertext, &[])?;
    let response_key = export_response_key(|label, out| context.export(label, out))?;

    Ok((plaintext, response_key))
}

/// Derives the response key from either side's HPKE context.
///
/// Taking a closure keeps the sender and receiver contexts on one code path, so the two
/// sides cannot drift in which labels they export or in what order.
fn export_response_key<E>(mut export: E) -> Result<ResponseKey, hpke::HpkeError>
where
    E: FnMut(&[u8], &mut [u8]) -> Result<(), hpke::HpkeError>,
{
    let mut key = [0u8; RESPONSE_KEY_LEN];
    let mut nonce = [0u8; RESPONSE_NONCE_LEN];

    if let Err(error) =
        export(RESPONSE_KEY_LABEL, &mut key).and_then(|()| export(RESPONSE_NONCE_LABEL, &mut nonce))
    {
        key.zeroize();
        nonce.zeroize();
        return Err(error);
    }

    Ok(ResponseKey { key, nonce })
}

/// Splits the `enc || ciphertext` framing of a sealed request.
///
/// Returns `None` when the payload is too short to carry both parts.
#[must_use]
pub const fn split(sealed_payload: &[u8]) -> Option<(&[u8], &[u8])> {
    if sealed_payload.len() <= ENCAPPED_KEY_LEN {
        return None;
    }

    Some(sealed_payload.split_at(ENCAPPED_KEY_LEN))
}

fn frame(encapped_key: &[u8; ENCAPPED_KEY_LEN], ciphertext: &[u8]) -> Vec<u8> {
    let mut sealed_payload = Vec::with_capacity(ENCAPPED_KEY_LEN + ciphertext.len());
    sealed_payload.extend_from_slice(encapped_key);
    sealed_payload.extend_from_slice(ciphertext);

    sealed_payload
}

#[cfg(test)]
mod tests {
    use hpke::Kem as _;

    use super::{ENCAPPED_KEY_LEN, Kem, PrivateKey, PublicKey, open_request, seal_request, split};

    fn keypair() -> (PrivateKey, PublicKey) {
        Kem::gen_keypair()
    }

    #[test]
    fn both_sides_derive_the_same_response_key() {
        let (private_key, public_key) = keypair();

        let (sealed, client_key) = seal_request(&public_key, b"inputs").expect("seal");
        let (plaintext, enclave_key) = open_request(&private_key, &sealed).expect("open");

        assert_eq!(plaintext, b"inputs");
        let sealed_response = enclave_key.seal(b"outcome").expect("seal response");
        assert_eq!(client_key.open(&sealed_response).expect("open"), b"outcome");
    }

    #[test]
    fn a_response_key_from_another_request_cannot_open_the_response() {
        let (private_key, public_key) = keypair();
        let (sealed, _) = seal_request(&public_key, b"inputs").expect("seal");
        let (_, enclave_key) = open_request(&private_key, &sealed).expect("open");
        let (other_sealed, other_client_key) = seal_request(&public_key, b"inputs").expect("seal");
        assert_ne!(sealed, other_sealed);

        let sealed_response = enclave_key.seal(b"outcome").expect("seal response");

        assert!(other_client_key.open(&sealed_response).is_err());
    }

    #[test]
    fn a_tampered_response_fails_authentication() {
        let (private_key, public_key) = keypair();
        let (sealed, client_key) = seal_request(&public_key, b"inputs").expect("seal");
        let (_, enclave_key) = open_request(&private_key, &sealed).expect("open");
        let mut sealed_response = enclave_key.seal(b"outcome").expect("seal response");
        *sealed_response.last_mut().expect("not empty") ^= 0x01;

        assert!(client_key.open(&sealed_response).is_err());
    }

    #[test]
    fn split_rejects_payloads_without_a_ciphertext() {
        assert!(split(&[]).is_none());
        assert!(split(&[0u8; ENCAPPED_KEY_LEN]).is_none());
    }
}

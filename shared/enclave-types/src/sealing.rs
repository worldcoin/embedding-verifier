//! The HPKE contract for payloads sealed to the enclave's encryption key.
//!
//! Both halves live here, next to the wire types, because this is a contract between the
//! enclave and its clients: a divergent ciphersuite or `info` string on either side fails
//! decryption with no diagnosable signal.

use hpke::{Deserializable, OpModeS, Serializable, single_shot_seal};

/// DHKEM(X25519, HKDF-SHA256) — RFC 9180 §7.1.
pub type Kem = hpke::kem::X25519HkdfSha256;

/// HKDF-SHA256 — RFC 9180 §7.2.
pub type Kdf = hpke::kdf::HkdfSha256;

/// AES-128-GCM — RFC 9180 §7.3.
///
/// Chosen to match the AEAD the `WorldID` OHTTP deployment already pins, and because Nitro
/// hosts have AES-NI.
pub type Aead = hpke::aead::AesGcm128;

/// HPKE `info`, binding a sealed payload to this service and payload version.
///
/// Changing this value silently invalidates every client. Version the string instead.
pub const INFO: &[u8] = b"embedding-verifier/v1/match-request";

/// Length of a serialized DHKEM(X25519) encapsulated key, and of the encryption public
/// key the enclave attests.
pub const ENCAPPED_KEY_LEN: usize = 32;

/// Seals a payload to the enclave's attested encryption key.
///
/// # Errors
///
/// Returns an error when `encryption_public_key` is not a valid X25519 public key, or
/// when encapsulation fails.
pub fn seal(
    encryption_public_key: &[u8; ENCAPPED_KEY_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, hpke::HpkeError> {
    let public_key =
        <<Kem as hpke::Kem>::PublicKey as Deserializable>::from_bytes(encryption_public_key)?;
    let (encapped_key, ciphertext) =
        single_shot_seal::<Aead, Kdf, Kem>(&OpModeS::Base, &public_key, INFO, plaintext, &[])?;

    Ok(frame(&encapped_key.to_bytes().into(), &ciphertext))
}

/// Splits the `enc || ciphertext` framing of a sealed payload.
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
    use super::{ENCAPPED_KEY_LEN, frame, split};

    #[test]
    fn framing_round_trips() {
        let sealed_payload = frame(&[7u8; ENCAPPED_KEY_LEN], b"ciphertext");

        let (encapped, ciphertext) = split(&sealed_payload).expect("frame should split");

        assert_eq!(encapped, [7u8; ENCAPPED_KEY_LEN]);
        assert_eq!(ciphertext, b"ciphertext");
    }

    #[test]
    fn split_rejects_payloads_without_a_ciphertext() {
        assert!(split(&[]).is_none());
        assert!(split(&[0u8; ENCAPPED_KEY_LEN]).is_none());
    }
}

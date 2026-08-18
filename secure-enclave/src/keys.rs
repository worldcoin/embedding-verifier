//! Boot-scoped key material.
//!
//! Both keypairs are generated in memory at boot and never persisted, sealed, or
//! shared across enclaves. There is deliberately no KMS-, disk-, or leader-derived key path.
//!
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use enclave_types::{
    EnclaveError,
    sealing::{self, PrivateKey, PublicKey, ResponseKey},
};
use hpke::Kem as _;

/// The field element a `BabyJubJub` `EdDSA` signature commits to.
pub type SigningMessage = ark_babyjubjub::Fq;

/// The X25519 keypair clients seal match requests to, under HPKE `mode_base`.
pub struct EncryptionKey {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl EncryptionKey {
    /// Generates a fresh HPKE keypair.
    #[must_use]
    pub fn generate() -> Self {
        let (private_key, public_key) = sealing::Kem::gen_keypair();

        Self {
            private_key,
            public_key,
        }
    }

    /// Returns the public key clients seal to.
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Opens a payload sealed to this key.
    ///
    /// Returns the plaintext and the key the response must be sealed under. Both come
    /// from one HPKE context, which is what lets the enclave answer without a
    /// client-held keypair (RFC 9180 §9.8).
    ///
    /// # Errors
    ///
    /// Returns [`EnclaveError::DecryptFailed`] when the payload is misframed, was sealed
    /// to another key, or fails authentication. One opaque error for all three.
    pub fn decrypt_request(
        &self,
        sealed_payload: &[u8],
    ) -> Result<(Vec<u8>, ResponseKey), EnclaveError> {
        sealing::open_request(&self.private_key, sealed_payload)
            .map_err(|_| EnclaveError::DecryptFailed)
    }
}

/// The `BabyJubJub` `EdDSA` keypair that signs match statements.
pub struct SigningKey {
    private_key: EdDSAPrivateKey,
    public_key: EdDSAPublicKey,
    /// Compressed encoding for NSM attestation, checked once at boot.
    compressed: [u8; 32],
}

impl SigningKey {
    /// Generates a fresh `BabyJubJub` `EdDSA` keypair.
    ///
    /// # Errors
    ///
    /// Returns an error when the generated public key cannot be compressed. Compressing
    /// once here keeps the fallible step at boot, so no request path can fail on it.
    pub fn generate() -> anyhow::Result<Self> {
        let private_key = EdDSAPrivateKey::random(&mut rand::rngs::OsRng);
        let public_key = private_key.public();
        let compressed = public_key.to_compressed_bytes().map_err(|error| {
            anyhow::anyhow!("failed to compress the signing public key: {error}")
        })?;

        Ok(Self {
            private_key,
            public_key,
            compressed,
        })
    }

    /// Returns the public key that verifies this boot's statements.
    #[must_use]
    pub const fn public_key(&self) -> &EdDSAPublicKey {
        &self.public_key
    }

    /// Compressed public key, as placed in the attestation document's `public_key` field.
    #[must_use]
    pub const fn compressed_public_key(&self) -> &[u8; 32] {
        &self.compressed
    }

    /// Signs one field element.
    ///
    /// Encoding a match statement into that element is deliberately not decided here —
    /// it is part of the statement format, which lands with the matches work.
    #[must_use]
    pub fn sign(&self, message: SigningMessage) -> EdDSASignature {
        self.private_key.sign(message)
    }
}

#[cfg(test)]
mod tests {
    use ark_babyjubjub::Fq;
    use enclave_types::{EnclaveError, sealing};

    use super::{EncryptionKey, SigningKey};

    fn seal_to(key: &EncryptionKey, plaintext: &[u8]) -> Vec<u8> {
        sealing::seal_request(key.public_key(), plaintext)
            .expect("sealing should succeed")
            .0
    }

    #[test]
    fn encryption_key_is_stable_for_one_key() {
        let key = EncryptionKey::generate();

        assert_eq!(key.public_key(), key.public_key());
    }

    #[test]
    fn separate_encryption_keys_are_distinct() {
        assert_ne!(
            EncryptionKey::generate().public_key(),
            EncryptionKey::generate().public_key()
        );
    }

    #[test]
    fn decrypt_request_opens_a_payload_sealed_to_the_attested_key() {
        let key = EncryptionKey::generate();
        let sealed = seal_to(&key, b"match inputs");

        let (plaintext, _) = key.decrypt_request(&sealed).expect("payload should open");

        assert_eq!(plaintext, b"match inputs");
    }

    #[test]
    fn decrypt_request_rejects_a_payload_sealed_to_another_key() {
        let recipient = EncryptionKey::generate();
        let sealed = seal_to(&EncryptionKey::generate(), b"match inputs");

        assert_eq!(
            recipient.decrypt_request(&sealed).err(),
            Some(EnclaveError::DecryptFailed)
        );
    }

    #[test]
    fn decrypt_request_rejects_a_tampered_ciphertext() {
        let key = EncryptionKey::generate();
        let mut sealed = seal_to(&key, b"match inputs");
        *sealed.last_mut().expect("sealed payload is not empty") ^= 0x01;

        assert_eq!(
            key.decrypt_request(&sealed).err(),
            Some(EnclaveError::DecryptFailed)
        );
    }

    #[test]
    fn decrypt_request_rejects_a_misframed_payload() {
        let key = EncryptionKey::generate();

        assert_eq!(
            key.decrypt_request(&[]).err(),
            Some(EnclaveError::DecryptFailed)
        );
        assert_eq!(
            key.decrypt_request(&[0u8; sealing::ENCAPPED_KEY_LEN]).err(),
            Some(EnclaveError::DecryptFailed)
        );
    }

    #[test]
    fn separate_signing_keys_are_distinct() {
        let first = SigningKey::generate().expect("signing key should generate");
        let second = SigningKey::generate().expect("signing key should generate");

        assert_ne!(first.public_key(), second.public_key());
    }

    #[test]
    fn signatures_verify_under_the_attested_public_key() {
        let key = SigningKey::generate().expect("signing key should generate");
        let message = Fq::from(42u64);

        let signature = key.sign(message);

        assert!(key.public_key().verify(message, &signature));
        assert!(!key.public_key().verify(Fq::from(43u64), &signature));
    }
}

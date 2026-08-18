//! Boot-scoped key material.
//!
//! Both keypairs are generated in memory at boot and never persisted, sealed, or
//! shared across enclaves. There is deliberately no KMS-, disk-, or leader-derived key path.
//!
use crypto_box::{PublicKey, SecretKey, aead::OsRng};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use enclave_types::EnclaveError;

/// The field element a `BabyJubJub` `EdDSA` signature commits to.
pub type SigningMessage = ark_babyjubjub::Fq;

/// The X25519 keypair clients seal match requests to, as a libsodium sealed box.
pub struct EncryptionKey {
    secret_key: SecretKey,
}

impl EncryptionKey {
    /// Generates a fresh X25519 keypair.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            secret_key: SecretKey::generate(&mut OsRng),
        }
    }

    /// Returns the public key clients seal to.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.secret_key.public_key()
    }

    /// Opens a sealed box addressed to this key.
    ///
    /// # Errors
    ///
    /// Returns [`EnclaveError::DecryptFailed`] when the ciphertext is malformed or is
    /// not addressed to this key.
    pub fn unseal(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EnclaveError> {
        self.secret_key
            .unseal(ciphertext)
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
    use crypto_box::aead::OsRng;
    use enclave_types::EnclaveError;

    use super::{EncryptionKey, SigningKey};

    fn seal_to(key: &EncryptionKey, plaintext: &[u8]) -> Vec<u8> {
        key.public_key()
            .seal(&mut OsRng, plaintext)
            .expect("sealing should succeed")
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
    fn unseal_opens_a_payload_sealed_to_the_attested_key() {
        let key = EncryptionKey::generate();
        let sealed = seal_to(&key, b"match inputs");

        let plaintext = key.unseal(&sealed).expect("payload should open");

        assert_eq!(plaintext, b"match inputs");
    }

    #[test]
    fn unseal_rejects_a_payload_sealed_to_another_key() {
        let recipient = EncryptionKey::generate();
        let sealed = seal_to(&EncryptionKey::generate(), b"match inputs");

        assert_eq!(recipient.unseal(&sealed), Err(EnclaveError::DecryptFailed));
    }

    #[test]
    fn unseal_rejects_a_tampered_ciphertext() {
        let key = EncryptionKey::generate();
        let mut sealed = seal_to(&key, b"match inputs");
        *sealed.last_mut().expect("sealed payload is not empty") ^= 0x01;

        assert_eq!(key.unseal(&sealed), Err(EnclaveError::DecryptFailed));
    }

    #[test]
    fn unseal_rejects_a_misframed_payload() {
        let key = EncryptionKey::generate();

        assert_eq!(key.unseal(&[]), Err(EnclaveError::DecryptFailed));
        assert_eq!(key.unseal(&[0u8; 64]), Err(EnclaveError::DecryptFailed));
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

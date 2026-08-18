//! Boot-scoped key material.
//!
//! Both keypairs are generated in memory at boot and never persisted, sealed, or
//! shared across enclaves. There is deliberately no KMS-, disk-, or leader-derived key path.

use crypto_box::{PublicKey, SecretKey, aead::OsRng};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};

/// The field element a `BabyJubJub` `EdDSA` signature commits to.
pub type SigningMessage = ark_babyjubjub::Fq;

/// The X25519 keypair whose public key is attested for this enclave boot.
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

    /// Returns the public key placed in the encryption-key attestation document.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.secret_key.public_key()
    }
}

/// The `BabyJubJub` `EdDSA` keypair that signs match statements.
pub struct SigningKey {
    private_key: EdDSAPrivateKey,
    public_key: EdDSAPublicKey,
}

impl SigningKey {
    /// Generates a fresh `BabyJubJub` `EdDSA` keypair.
    #[must_use]
    pub fn generate() -> Self {
        let private_key = EdDSAPrivateKey::random(&mut rand::rngs::OsRng);
        let public_key = private_key.public();

        Self {
            private_key,
            public_key,
        }
    }

    /// Returns the public key that verifies this boot's statements.
    #[must_use]
    pub const fn public_key(&self) -> &EdDSAPublicKey {
        &self.public_key
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

    use super::{EncryptionKey, SigningKey};

    #[test]
    fn separate_encryption_keys_are_distinct() {
        assert_ne!(
            EncryptionKey::generate().public_key(),
            EncryptionKey::generate().public_key()
        );
    }

    #[test]
    fn separate_signing_keys_are_distinct() {
        let first = SigningKey::generate();
        let second = SigningKey::generate();

        assert_ne!(first.public_key(), second.public_key());
    }

    #[test]
    fn signatures_verify_under_the_attested_public_key() {
        let key = SigningKey::generate();
        let message = Fq::from(42u64);

        let signature = key.sign(message);

        assert!(key.public_key().verify(message, &signature));
        assert!(!key.public_key().verify(Fq::from(43u64), &signature));
    }
}

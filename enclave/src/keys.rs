//! Boot-scoped signing key material.
//!
//! The keypair is generated in memory at boot and never persisted, sealed, or shared across
//! enclaves. There is deliberately no KMS-, disk-, or leader-derived key path. The sealed
//! channel endpoint lives in [`crypto::sealed_channel::Responder`] and is owned by
//! [`crate::state::EnclaveState`].

use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};

/// The field element a `BabyJubJub` `EdDSA` signature commits to.
pub type SigningMessage = ark_babyjubjub::Fq;

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

    use super::SigningKey;

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

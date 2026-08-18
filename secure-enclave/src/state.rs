//! Boot-scoped state owned by the secure enclave.

use std::sync::Arc;

use crypto_box::PublicKey;
use eddsa_babyjubjub::EdDSAPublicKey;
use enclave_types::EnclaveError;

use crate::{
    attestation::Attestor,
    face_engine::FaceComparator,
    keys::{EncryptionKey, SigningKey},
};

/// Immutable state generated once during enclave boot.
pub struct EnclaveState {
    encryption_key: EncryptionKey,
    signing_key: SigningKey,
    attestor: Arc<dyn Attestor>,
    face_engine: Arc<dyn FaceComparator>,
}

impl EnclaveState {
    /// Generates fresh boot-scoped keys, with the provided attestor and Face Engine.
    #[must_use]
    pub fn generate(attestor: Arc<dyn Attestor>, face_engine: Arc<dyn FaceComparator>) -> Self {
        let encryption_key = EncryptionKey::generate();
        let signing_key = SigningKey::generate();
        tracing::info!("generated boot-scoped encryption and signing keys");

        Self {
            encryption_key,
            signing_key,
            attestor,
            face_engine,
        }
    }

    /// Returns the X25519 public key attested for this enclave boot.
    #[must_use]
    pub fn encryption_public_key(&self) -> PublicKey {
        self.encryption_key.public_key()
    }

    /// Returns the `BabyJubJub` public key that verifies this boot's statements.
    #[must_use]
    pub const fn signing_public_key(&self) -> &EdDSAPublicKey {
        self.signing_key.public_key()
    }

    /// Returns the Face Engine used for enclave match operations.
    #[must_use]
    pub fn face_engine(&self) -> &dyn FaceComparator {
        self.face_engine.as_ref()
    }

    /// Attests the encryption public key.
    ///
    /// # Errors
    ///
    /// Propagates the [`Attestor`] failure.
    pub fn attest_encryption_key(&self) -> Result<Vec<u8>, EnclaveError> {
        let public_key = self.encryption_public_key().to_bytes();
        self.attestor.attest_public_key(&public_key)
    }

    /// Attests the signing public key.
    ///
    /// # Errors
    ///
    /// Propagates the [`Attestor`] failure.
    pub fn attest_signing_key(&self) -> Result<Vec<u8>, EnclaveError> {
        let public_key = self
            .signing_public_key()
            .to_compressed_bytes()
            .map_err(|error| {
                tracing::error!(%error, "failed to serialize the signing public key");
                EnclaveError::AttestationFailed
            })?;
        self.attestor.attest_public_key(&public_key)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::EnclaveState;
    use crate::test_support::{EchoAttestor, state_with};

    fn state() -> Arc<EnclaveState> {
        state_with(Arc::new(EchoAttestor))
    }

    #[test]
    fn keys_are_stable_for_one_state() {
        let state = state();

        assert_eq!(state.encryption_public_key(), state.encryption_public_key());
        assert_eq!(state.signing_public_key(), state.signing_public_key());
    }

    #[test]
    fn separate_states_receive_separate_keys() {
        let first = state();
        let second = state();

        assert_ne!(
            first.encryption_public_key(),
            second.encryption_public_key()
        );
        assert_ne!(first.signing_public_key(), second.signing_public_key());
    }

    #[test]
    fn each_key_is_attested_in_its_own_document() {
        let state = state();

        assert_eq!(
            state.attest_encryption_key(),
            Ok(state.encryption_public_key().to_bytes().to_vec())
        );
        assert_eq!(
            state.attest_signing_key(),
            Ok(state
                .signing_public_key()
                .to_compressed_bytes()
                .expect("generated BabyJubJub public key serializes")
                .to_vec())
        );
    }
}

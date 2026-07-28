//! Boot-scoped state owned by the secure enclave.

use std::sync::Arc;

use crypto_box::{SecretKey, aead::OsRng};
use enclave_types::EnclaveError;

use crate::face_engine::FaceComparator;

/// Immutable state generated once during enclave boot.
pub struct EnclaveState {
    transit_secret_key: SecretKey,
    face_engine: Arc<dyn FaceComparator>,
}

impl EnclaveState {
    /// Generates fresh boot-scoped enclave state with the provided Face Engine.
    #[must_use]
    pub fn generate(face_engine: Arc<dyn FaceComparator>) -> Self {
        let transit_secret_key = SecretKey::generate(&mut OsRng);
        tracing::info!("generated boot-scoped transit key");

        Self {
            transit_secret_key,
            face_engine,
        }
    }

    /// Returns the X25519 public key used to encrypt requests for this enclave boot.
    #[must_use]
    pub fn transit_public_key(&self) -> [u8; 32] {
        self.transit_secret_key.public_key().to_bytes()
    }

    /// Returns the Face Engine used for enclave match operations.
    #[must_use]
    pub fn face_engine(&self) -> &dyn FaceComparator {
        self.face_engine.as_ref()
    }

    /// Unseals a libsodium sealed box addressed to this boot's transit public key.
    ///
    /// The client encrypts to the enclave public key with an ephemeral sender key
    /// (anonymous sealed box), so this provides confidentiality and integrity of the
    /// ciphertext but no sender authentication — by design, as callers are not
    /// pre-registered and provenance is enforced downstream, not here.
    ///
    /// # Errors
    ///
    /// Returns [`EnclaveError::DecryptFailed`] when the ciphertext is malformed or is
    /// not addressed to this key. The error is deliberately opaque: no plaintext,
    /// ciphertext, or key material is surfaced or logged.
    pub fn unseal(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EnclaveError> {
        self.transit_secret_key
            .unseal(ciphertext)
            .map_err(|_| EnclaveError::DecryptFailed)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use enclave_types::EnclaveError;

    use super::EnclaveState;
    use crate::face_engine::{ComparisonScores, FaceComparator};

    struct NoopFaceEngine;

    impl FaceComparator for NoopFaceEngine {
        fn compare_reference_to_probes(
            &self,
            _: &[u8],
            _: &[u8],
            _: &[u8],
        ) -> Result<ComparisonScores, EnclaveError> {
            Err(EnclaveError::NotReady)
        }
    }

    fn state() -> EnclaveState {
        EnclaveState::generate(Arc::new(NoopFaceEngine))
    }

    #[test]
    fn transit_key_is_stable_for_one_state() {
        let state = state();

        assert_eq!(state.transit_public_key(), state.transit_public_key());
    }

    #[test]
    fn separate_states_receive_separate_transit_keys() {
        let first = state();
        let second = state();

        assert_ne!(first.transit_public_key(), second.transit_public_key());
    }
}

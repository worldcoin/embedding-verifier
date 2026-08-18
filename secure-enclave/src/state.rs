//! Boot-scoped state owned by the secure enclave.

use std::sync::Arc;

use enclave_types::{EnclaveError, sealing, sealing::ResponseKey};

use crate::{
    attestation::Attestor,
    face_engine::FaceComparator,
    keys::{EncryptionKey, SIGNING_PUBLIC_KEY_LEN, SigningKey},
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
    ///
    /// # Errors
    ///
    /// Returns an error when a key cannot be generated.
    pub fn generate(
        attestor: Arc<dyn Attestor>,
        face_engine: Arc<dyn FaceComparator>,
    ) -> anyhow::Result<Self> {
        let encryption_key = EncryptionKey::generate();
        let signing_key = SigningKey::generate()?;
        tracing::info!("generated boot-scoped encryption and signing keys");

        Ok(Self {
            encryption_key,
            signing_key,
            attestor,
            face_engine,
        })
    }

    /// Returns the HPKE public key clients seal requests to for this enclave boot.
    #[must_use]
    pub const fn encryption_public_key(&self) -> [u8; sealing::ENCAPPED_KEY_LEN] {
        self.encryption_key.public_key_bytes()
    }

    /// Returns the compressed `BabyJubJub` public key that verifies this boot's statements.
    #[must_use]
    pub const fn signing_public_key(&self) -> [u8; SIGNING_PUBLIC_KEY_LEN] {
        self.signing_key.public_key_bytes()
    }

    /// Returns the signing key used for match statements.
    #[must_use]
    pub const fn signing_key(&self) -> &SigningKey {
        &self.signing_key
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
        self.attestor
            .attest_public_key(&self.encryption_public_key())
    }

    /// Attests the signing public key.
    ///
    /// # Errors
    ///
    /// Propagates the [`Attestor`] failure.
    pub fn attest_signing_key(&self) -> Result<Vec<u8>, EnclaveError> {
        self.attestor.attest_public_key(&self.signing_public_key())
    }

    /// Opens an HPKE payload sealed to this boot's encryption key.
    ///
    /// Returns the plaintext and the key its response must be sealed under.
    ///
    /// # Errors
    ///
    /// Returns [`EnclaveError::DecryptFailed`]. See
    /// [`EncryptionKey::decrypt_request`] for why the error is uniform and opaque.
    pub fn unseal(&self, sealed_payload: &[u8]) -> Result<(Vec<u8>, ResponseKey), EnclaveError> {
        self.encryption_key.decrypt_request(sealed_payload)
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
            Ok(state.encryption_public_key().to_vec())
        );
        assert_eq!(
            state.attest_signing_key(),
            Ok(state.signing_public_key().to_vec())
        );
    }
}

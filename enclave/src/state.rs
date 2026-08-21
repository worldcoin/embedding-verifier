//! Boot-scoped state owned by the enclave.

use std::sync::Arc;
use std::time::Duration;

use attested_channel::channel::{ENCRYPTION_KEY_LEN, Responder, UnwrapErr};
use eddsa_babyjubjub::EdDSAPublicKey;
use enclave_types::EnclaveError;
use getrandom::SysRng;

use crate::{
    attestation::Attestor,
    attested_key::{AttestedKey, MAX_SERVED_AGE},
    face_engine::FaceComparator,
    keys::SigningKey,
};

/// Immutable state generated once during enclave boot.
pub struct EnclaveState {
    responder: Responder,
    signing_key: SigningKey,
    attested_encryption_key: AttestedKey,
    attested_signing_key: AttestedKey,
    face_engine: Arc<dyn FaceComparator>,
}

impl EnclaveState {
    /// Generates fresh boot-scoped keys and attests both, with the provided attestor and Face Engine.
    ///
    /// Attesting here rather than per request means a signing key that will not serialize, or an NSM
    /// that will not answer, fails the boot instead of every later request — and leaves both caches
    /// populated before the server accepts anything.
    ///
    /// # Errors
    ///
    /// Returns [`EnclaveError`] if the signing public key cannot be serialized, or if either key
    /// cannot be attested.
    pub fn generate(
        attestor: Arc<dyn Attestor>,
        face_engine: Arc<dyn FaceComparator>,
    ) -> Result<Self, EnclaveError> {
        Self::generate_with(attestor, face_engine, MAX_SERVED_AGE)
    }

    /// Builds state whose cached documents have already aged out.
    ///
    /// Test-only hook for the readiness path; production always uses [`MAX_SERVED_AGE`].
    ///
    /// # Errors
    ///
    /// As [`Self::generate`].
    #[cfg(test)]
    pub(crate) fn generate_stale(
        attestor: Arc<dyn Attestor>,
        face_engine: Arc<dyn FaceComparator>,
    ) -> Result<Self, EnclaveError> {
        Self::generate_with(attestor, face_engine, Duration::ZERO)
    }

    fn generate_with(
        attestor: Arc<dyn Attestor>,
        face_engine: Arc<dyn FaceComparator>,
        max_served_age: Duration,
    ) -> Result<Self, EnclaveError> {
        let mut rng = UnwrapErr(SysRng);
        let responder = Responder::generate(&mut rng);
        let signing_key = SigningKey::generate();
        tracing::info!("generated boot-scoped sealed channel and signing keys");

        // Serialized once here rather than on every attestation: it cannot fail for a key this
        // process just generated, and if it somehow does the boot is the place to find out.
        let signing_public_key =
            signing_key
                .public_key()
                .to_compressed_bytes()
                .map_err(|error| {
                    tracing::error!(%error, "failed to serialize the signing public key");
                    EnclaveError::AttestationFailed
                })?;

        let attested_encryption_key = AttestedKey::attest_now(
            Arc::clone(&attestor),
            responder.public_key().to_vec(),
            max_served_age,
        )?;
        let attested_signing_key =
            AttestedKey::attest_now(attestor, signing_public_key.to_vec(), max_served_age)?;

        Ok(Self {
            responder,
            signing_key,
            attested_encryption_key,
            attested_signing_key,
            face_engine,
        })
    }

    /// Returns the responder that opens sealed requests for this boot.
    #[must_use]
    pub const fn responder(&self) -> &Responder {
        &self.responder
    }

    /// Returns the X25519 public key attested for this enclave boot.
    #[must_use]
    pub const fn encryption_public_key(&self) -> [u8; ENCRYPTION_KEY_LEN] {
        self.responder.public_key()
    }

    /// Returns the signing key for this boot.
    #[must_use]
    pub const fn signing_key(&self) -> &SigningKey {
        &self.signing_key
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

    /// The attestation document for the encryption public key, from cache.
    ///
    /// # Errors
    ///
    /// [`EnclaveError::NotReady`] once the cached document has aged out.
    pub fn encryption_key_attestation(&self) -> Result<Vec<u8>, EnclaveError> {
        self.attested_encryption_key.document()
    }

    /// The attestation document for the signing public key, from cache.
    ///
    /// # Errors
    ///
    /// [`EnclaveError::NotReady`] once the cached document has aged out.
    pub fn signing_key_attestation(&self) -> Result<Vec<u8>, EnclaveError> {
        self.attested_signing_key.document()
    }

    /// Whether both cached documents are still young enough to hand out.
    ///
    /// Readiness rests on this: an enclave that cannot produce an attestation cannot serve
    /// assignments, and must not report healthy while that route fails.
    #[must_use]
    pub fn attestations_are_servable(&self) -> bool {
        self.attested_encryption_key.is_servable() && self.attested_signing_key.is_servable()
    }

    /// Age of the staler of the two cached documents.
    #[must_use]
    pub fn oldest_attestation_age(&self) -> Duration {
        self.attested_encryption_key
            .age()
            .max(self.attested_signing_key.age())
    }

    /// Re-attests both keys, replacing the cached documents.
    ///
    /// Blocking, so callers on the async runtime must go through `spawn_blocking`.
    ///
    /// # Errors
    ///
    /// Propagates the first attestation failure, leaving that key's previous document in place.
    pub fn refresh_attestations(&self) -> Result<(), EnclaveError> {
        self.attested_encryption_key.refresh()?;
        self.attested_signing_key.refresh()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use enclave_types::EnclaveError;

    use super::EnclaveState;
    use crate::test_support::{
        EchoAttestor, FailingAttestor, UnusedFaceEngine, stale_state_with, state_with,
    };

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
            state.encryption_key_attestation(),
            Ok(state.encryption_public_key().to_vec())
        );
        assert_eq!(
            state.signing_key_attestation(),
            Ok(state
                .signing_public_key()
                .to_compressed_bytes()
                .expect("generated BabyJubJub public key serializes")
                .to_vec())
        );
    }

    /// An enclave that cannot prove its own identity must not reach the point of serving.
    #[test]
    fn an_attestor_that_fails_fails_the_boot() {
        let error =
            EnclaveState::generate(Arc::new(FailingAttestor), Arc::new(UnusedFaceEngine)).err();

        assert_eq!(error, Some(EnclaveError::AttestationFailed));
    }

    #[test]
    fn documents_past_the_ceiling_are_neither_served_nor_reported_servable() {
        let state = stale_state_with(Arc::new(EchoAttestor));

        assert!(!state.attestations_are_servable());
        assert_eq!(
            state.encryption_key_attestation(),
            Err(EnclaveError::NotReady)
        );
        assert_eq!(state.signing_key_attestation(), Err(EnclaveError::NotReady));
    }

    #[test]
    fn a_refresh_keeps_the_documents_servable() {
        let state = state();

        state
            .refresh_attestations()
            .expect("refresh should succeed");

        assert!(state.attestations_are_servable());
        assert_eq!(
            state.encryption_key_attestation(),
            Ok(state.encryption_public_key().to_vec())
        );
    }
}

//! Test doubles shared across the enclave's unit tests.

use std::sync::Arc;

use enclave_types::EnclaveError;

use crate::{
    attestation::Attestor,
    face_engine::{ComparisonScores, FaceComparator},
    state::EnclaveState,
};

/// Returns the attested key as its own "document", so tests can tell the two apart.
pub struct EchoAttestor;

impl Attestor for EchoAttestor {
    fn attest_public_key(&self, public_key: &[u8]) -> Result<Vec<u8>, EnclaveError> {
        Ok(public_key.to_vec())
    }
}

pub struct FailingAttestor;

impl Attestor for FailingAttestor {
    fn attest_public_key(&self, _: &[u8]) -> Result<Vec<u8>, EnclaveError> {
        Err(EnclaveError::AttestationFailed)
    }
}

/// Panics if a test reaches it, for paths that must reject before comparing faces.
pub struct UnusedFaceEngine;

impl FaceComparator for UnusedFaceEngine {
    fn compare_reference_to_probes(
        &self,
        _: &[u8],
        _: &[u8],
        _: &[u8],
    ) -> Result<ComparisonScores, EnclaveError> {
        panic!("Face Engine was called unexpectedly")
    }
}

/// Builds state whose Face Engine must not be called.
pub fn state_with(attestor: Arc<dyn Attestor>) -> Arc<EnclaveState> {
    Arc::new(EnclaveState::generate(attestor, Arc::new(UnusedFaceEngine)))
}

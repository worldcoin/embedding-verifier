//! Test doubles shared across the enclave's unit tests.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use deepface_protocol::messages::FailureReason;
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

/// Counts attestations and makes every document distinct, so a cached document is
/// distinguishable from a re-attested one.
pub struct CountingAttestor {
    calls: AtomicUsize,
    succeed_for: usize,
}

impl CountingAttestor {
    /// An attestor that always succeeds.
    pub const fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            succeed_for: usize::MAX,
        }
    }

    /// An attestor that succeeds `calls` times and fails from then on, for exercising a refresh
    /// that fails after construction already populated the cache.
    pub const fn failing_after(calls: usize) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            succeed_for: calls,
        }
    }

    /// How many attestations have been requested.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl Attestor for CountingAttestor {
    fn attest_public_key(&self, public_key: &[u8]) -> Result<Vec<u8>, EnclaveError> {
        let call = self.calls.fetch_add(1, Ordering::Relaxed);
        if call >= self.succeed_for {
            return Err(EnclaveError::AttestationFailed);
        }

        // The call index makes each document unique without needing a real NSM.
        let mut document = public_key.to_vec();
        document.push(u8::try_from(call % 256).unwrap_or_default());

        Ok(document)
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
    ) -> Result<ComparisonScores, FailureReason> {
        panic!("Face Engine was called unexpectedly")
    }
}

/// Builds state whose Face Engine must not be called.
pub fn state_with(attestor: Arc<dyn Attestor>) -> Arc<EnclaveState> {
    Arc::new(
        EnclaveState::generate(attestor, Arc::new(UnusedFaceEngine))
            .expect("boot state should generate"),
    )
}

/// Builds state whose cached attestation documents have already aged out.
pub fn stale_state_with(attestor: Arc<dyn Attestor>) -> Arc<EnclaveState> {
    Arc::new(
        EnclaveState::generate_stale(attestor, Arc::new(UnusedFaceEngine))
            .expect("boot state should generate"),
    )
}

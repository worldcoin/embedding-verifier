//! Pontifex server setup and operation routing.

use std::sync::Arc;

use anyhow::Context;
use enclave_types::{GetTransitKeyRequest, HealthRequest, MatchRequest};
use pontifex::Router;

mod health;
mod matches;
mod transit_key;

use crate::state::EnclaveState;

/// Starts the enclave's Pontifex server on the provided vsock port.
///
/// # Errors
///
/// Returns an error when Pontifex cannot listen for or serve requests.
pub async fn start(state: Arc<EnclaveState>, port: u32) -> anyhow::Result<()> {
    router(state)
        .serve(port)
        .await
        .context("failed to serve Pontifex")
}

fn router(state: Arc<EnclaveState>) -> Router<Arc<EnclaveState>> {
    Router::with_state(state)
        .route::<HealthRequest, _, _>(health::handler)
        .route::<GetTransitKeyRequest, _, _>(transit_key::handler)
        .route::<MatchRequest, _, _>(matches::handler)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use enclave_types::EnclaveError;

    use super::router;
    use crate::{
        face_engine::{ComparisonScores, FaceComparator},
        state::EnclaveState,
    };

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

    #[test]
    fn router_registers_enclave_operations() {
        let state = EnclaveState::generate(Arc::new(NoopFaceEngine));
        let _router = router(Arc::new(state));
    }
}

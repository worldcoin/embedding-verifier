use std::sync::Arc;

use enclave_types::{EnclaveError, HealthRequest};

use crate::state::EnclaveState;

/// Reports whether the enclave can serve requests.
///
/// Attestation freshness belongs here, not just on the assignment route: without a servable
/// document that route fails, so answering `Ok` would hold a broken enclave in rotation. Silent by
/// design — the host probes continuously, and the refresh task logs the cause.
pub async fn handler(state: Arc<EnclaveState>, _: HealthRequest) -> Result<(), EnclaveError> {
    if state.attestations_are_servable() {
        return Ok(());
    }

    Err(EnclaveError::NotReady)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use enclave_types::{EnclaveError, HealthRequest};

    use super::handler;
    use crate::test_support::{EchoAttestor, stale_state_with, state_with};

    #[tokio::test]
    async fn a_servable_enclave_is_healthy() {
        let state = state_with(Arc::new(EchoAttestor));

        assert_eq!(handler(state, HealthRequest).await, Ok(()));
    }

    #[tokio::test]
    async fn an_aged_out_cache_reports_not_ready() {
        let state = stale_state_with(Arc::new(EchoAttestor));

        assert_eq!(
            handler(state, HealthRequest).await,
            Err(EnclaveError::NotReady)
        );
    }
}

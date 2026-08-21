use std::sync::Arc;

use enclave_types::{EnclaveError, HealthRequest};

use crate::state::EnclaveState;

/// Reports whether the enclave can serve requests.
///
/// Attestation freshness is part of readiness, not a detail of the assignment route: without a
/// servable document that route fails, so answering `Ok` here would hold a broken enclave in
/// rotation. Deliberately silent — the host probes this continuously, and the refresh task already
/// logs the failure that caused it.
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

    /// Readiness has to fall with the attestation cache, or the host keeps routing to an enclave
    /// whose assignment route is failing.
    #[tokio::test]
    async fn an_aged_out_cache_reports_not_ready() {
        let state = stale_state_with(Arc::new(EchoAttestor));

        assert_eq!(
            handler(state, HealthRequest).await,
            Err(EnclaveError::NotReady)
        );
    }
}

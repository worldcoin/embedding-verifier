//! Pontifex server setup and operation routing.

use std::sync::Arc;

use anyhow::Context;
use enclave_types::{GetEnclaveKeysRequest, HealthRequest, MatchRequest};
use pontifex::Router;

mod enclave_keys;
mod health;
mod matches;

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
        .route::<GetEnclaveKeysRequest, _, _>(enclave_keys::handler)
        .route::<MatchRequest, _, _>(matches::handler)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::router;
    use crate::test_support::{FailingAttestor, state_with};

    #[test]
    fn router_registers_enclave_operations() {
        let _router = router(state_with(Arc::new(FailingAttestor)));
    }
}

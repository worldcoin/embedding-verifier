//! Pontifex server setup and operation routing.

use std::sync::Arc;

use anyhow::Context;
use enclave_types::{BindPcpRequest, GetTransitKeyRequest, HealthRequest};
use pontifex::Router;

mod health;
mod pcp_binding;
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
        .route::<BindPcpRequest, _, _>(pcp_binding::handler)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::router;
    use crate::state::EnclaveState;

    #[test]
    fn router_registers_enclave_operations() {
        let _router = router(Arc::new(EnclaveState::generate()));
    }
}

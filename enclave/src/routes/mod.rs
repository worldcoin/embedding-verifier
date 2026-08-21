//! Pontifex operation routing.

use std::sync::Arc;

use enclave_types::{GetEnclaveKeysRequest, HealthRequest, MatchRequest};
use pontifex::Router;

mod enclave_keys;
mod health;
mod matches;

use crate::state::EnclaveState;

/// Builds the router with all enclave operations.
pub(crate) fn router(state: Arc<EnclaveState>) -> Router<Arc<EnclaveState>> {
    Router::with_state(state)
        .route::<HealthRequest, _, _>(health::handler)
        .route::<GetEnclaveKeysRequest, _, _>(enclave_keys::handler)
        .route::<MatchRequest, _, _>(matches::handler)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::router;
    use crate::test_support::{EchoAttestor, state_with};

    #[test]
    fn router_registers_enclave_operations() {
        let _router = router(state_with(Arc::new(EchoAttestor)));
    }
}

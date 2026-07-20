use std::sync::Arc;

use crate::enclave::EnclaveClient;

use super::Environment;

/// Dependencies shared by API request handlers.
#[derive(Clone)]
pub struct AppState {
    environment: Environment,
    enclave_client: Arc<dyn EnclaveClient>,
}

impl AppState {
    /// Creates API state from the runtime environment and enclave client.
    #[must_use]
    pub const fn new(environment: Environment, enclave_client: Arc<dyn EnclaveClient>) -> Self {
        Self {
            environment,
            enclave_client,
        }
    }

    /// Returns the runtime environment.
    #[must_use]
    pub const fn environment(&self) -> Environment {
        self.environment
    }

    /// Returns a shared secure-enclave client.
    #[must_use]
    pub fn enclave_client(&self) -> Arc<dyn EnclaveClient> {
        Arc::clone(&self.enclave_client)
    }
}

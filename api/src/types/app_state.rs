use std::sync::Arc;

use crate::config::Config;
use crate::enclave::EnclaveClient;
use crate::readiness::Readiness;
use crate::telemetry::Metrics;

/// Dependencies shared by API request handlers.
#[derive(Clone)]
pub struct AppState {
    config: Arc<Config>,
    enclave_client: Arc<dyn EnclaveClient>,
    readiness: Arc<Readiness>,
    metrics: Arc<Metrics>,
}

impl AppState {
    /// Creates API state from resolved configuration and its dependencies.
    #[must_use]
    pub fn new(
        config: Arc<Config>,
        enclave_client: Arc<dyn EnclaveClient>,
        readiness: Arc<Readiness>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            config,
            enclave_client,
            readiness,
            metrics,
        }
    }

    /// Returns the resolved service configuration.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Returns a shared secure-enclave client.
    #[must_use]
    pub fn enclave_client(&self) -> Arc<dyn EnclaveClient> {
        Arc::clone(&self.enclave_client)
    }

    /// Returns the shared readiness state.
    #[must_use]
    pub fn readiness(&self) -> Arc<Readiness> {
        Arc::clone(&self.readiness)
    }

    /// Returns the shared metrics publisher.
    #[must_use]
    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }
}

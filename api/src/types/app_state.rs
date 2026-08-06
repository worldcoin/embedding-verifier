use std::sync::Arc;

use crate::enclave::{EnclaveClient, EnclaveClientError};

use super::{Environment, TransitKeyCache};

/// Dependencies shared by API request handlers.
#[derive(Clone)]
pub struct AppState {
    environment: Environment,
    enclave_client: Arc<dyn EnclaveClient>,
    transit_key_cache: Arc<TransitKeyCache>,
}

impl AppState {
    /// Creates API state from the runtime environment and enclave client.
    #[must_use]
    pub fn new(environment: Environment, enclave_client: Arc<dyn EnclaveClient>) -> Self {
        Self {
            environment,
            enclave_client,
            transit_key_cache: Arc::new(TransitKeyCache::new()),
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

    /// Returns the cache for the enclave's attested transit key.
    #[must_use]
    pub fn transit_key_cache(&self) -> &TransitKeyCache {
        &self.transit_key_cache
    }

    /// Reports a failed enclave call so boot-scoped caches can track enclave liveness.
    ///
    /// Every route that talks to the enclave calls this, which is what keeps the signal
    /// continuous: the readiness probe alone exercises it on every poll.
    ///
    /// Only [`EnclaveClientError::Transport`] invalidates. It means the vsock connection
    /// could not be established or completed, which is the host's only observable of an
    /// enclave that went away and came back holding a new transit key. A
    /// [`EnclaveClientError::Timeout`] does not: the connection was fine and the enclave
    /// was merely slow, so discarding the attestation would pay a real cost for no
    /// signal — and a restart that a timeout masked still surfaces on the next probe.
    pub fn observe_enclave_failure(&self, error: &EnclaveClientError) {
        if matches!(error, EnclaveClientError::Transport(_)) {
            self.transit_key_cache.invalidate();
        }
    }
}

use std::sync::Arc;

use crate::{Environment, challenge_fetch::ChallengeSource, enclave::EnclaveClient};

/// Dependencies shared by API request handlers.
#[derive(Clone)]
pub struct AppState {
    environment: Environment,
    enclave_client: Arc<dyn EnclaveClient>,
    challenge_source: Arc<dyn ChallengeSource>,
}

impl AppState {
    /// Creates API state from the runtime environment and enclave client.
    #[must_use]
    #[must_use]
    pub fn new(
        environment: Environment,
        enclave_client: Arc<dyn EnclaveClient>,
        challenge_source: Arc<dyn ChallengeSource>,
    ) -> Self {
        Self {
            environment,
            enclave_client,
            challenge_source,
        }
    }

    /// Returns the runtime environment.
    #[must_use]
    pub const fn environment(&self) -> Environment {
        self.environment
    }

    /// Returns a shared enclave client.
    #[must_use]
    pub fn enclave_client(&self) -> Arc<dyn EnclaveClient> {
        Arc::clone(&self.enclave_client)
    }

    /// Returns the challenge-image source.
    #[must_use]
    pub fn challenge_source(&self) -> Arc<dyn ChallengeSource> {
        Arc::clone(&self.challenge_source)
    }
}

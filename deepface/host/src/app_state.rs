use std::sync::Arc;

use tokio::sync::watch;

use crate::key_registry::{KeyRegistry, SigningPublicKey};
use crate::{Environment, challenge_fetcher::ChallengeSource, enclave::EnclaveClient};

/// Dependencies shared by API request handlers.
#[derive(Clone)]
pub struct AppState {
    environment: Environment,
    enclave_client: Arc<dyn EnclaveClient>,
    challenge_source: Arc<dyn ChallengeSource>,
    key_registry: Arc<dyn KeyRegistry>,
    registered_signing_key: watch::Receiver<Option<SigningPublicKey>>,
}

impl AppState {
    /// Creates API state from the runtime environment and enclave client.
    ///
    /// `registered_signing_key` carries this boot's key once the registration task has written it,
    /// and is what readiness waits on.
    #[must_use]
    pub fn new(
        environment: Environment,
        enclave_client: Arc<dyn EnclaveClient>,
        challenge_source: Arc<dyn ChallengeSource>,
        key_registry: Arc<dyn KeyRegistry>,
        registered_signing_key: watch::Receiver<Option<SigningPublicKey>>,
    ) -> Self {
        Self {
            environment,
            enclave_client,
            challenge_source,
            key_registry,
            registered_signing_key,
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

    /// Returns the `Signing Key` registry.
    #[must_use]
    pub fn key_registry(&self) -> Arc<dyn KeyRegistry> {
        Arc::clone(&self.key_registry)
    }

    /// This boot's signing key, once it is in the registry.
    ///
    /// `None` until then: no verifier can check a statement this enclave signs, so the host is not
    /// ready to serve matches.
    #[must_use]
    pub fn registered_signing_key(&self) -> Option<SigningPublicKey> {
        *self.registered_signing_key.borrow()
    }
}

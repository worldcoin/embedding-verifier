//! Test doubles shared across the host's integration tests.

use std::sync::Arc;

use async_trait::async_trait;
use flamingo_verifier_enclave_types::{MatchRequest, MatchResponse};
use flamingo_verifier_host::enclave::{EnclaveClient, EnclaveClientError};
use flamingo_verifier_host::{AppState, Environment};

/// An [`EnclaveClient`] answering from fixed results.
///
/// Unconfigured operations panic, so a route asking for the wrong key fails loudly.
#[derive(Default)]
pub struct StubEnclaveClient {
    /// `None` is healthy, so only a test about readiness has to say anything.
    pub health: Option<Result<(), EnclaveClientError>>,
    pub encryption_key: Option<Result<Vec<u8>, EnclaveClientError>>,
    pub match_result: Option<Result<MatchResponse, EnclaveClientError>>,
    /// Asserted against the sealed body the route forwards, if set.
    pub expected_body: Option<Vec<u8>>,
}

#[async_trait]
impl EnclaveClient for StubEnclaveClient {
    async fn health(&self) -> Result<(), EnclaveClientError> {
        self.health.clone().unwrap_or(Ok(()))
    }

    async fn encryption_key_attestation(&self) -> Result<Vec<u8>, EnclaveClientError> {
        self.encryption_key
            .clone()
            .expect("route asked for the encryption key but the stub was not configured to answer")
    }

    async fn run_match(&self, request: MatchRequest) -> Result<MatchResponse, EnclaveClientError> {
        if let Some(expected) = &self.expected_body {
            assert_eq!(&request.body, expected);
        }

        self.match_result
            .clone()
            .expect("route ran a match but the stub was not configured to answer")
    }
}

/// Builds an [`AppState`] backed by `client`.
pub fn state_with(client: StubEnclaveClient) -> AppState {
    AppState::new(Environment::Development, Arc::new(client))
}

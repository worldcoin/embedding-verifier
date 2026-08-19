//! Test doubles shared across the host's integration tests.

use std::sync::Arc;

use async_trait::async_trait;
use enclave_types::{GetEnclaveKeysResponse, MatchRequest, MatchResponse};
use host::enclave::{EnclaveClient, EnclaveClientError};
use host::{AppState, Environment};

/// An [`EnclaveClient`] answering from fixed results.
///
/// Unconfigured operations panic, so a route calling the wrong one fails loudly.
#[derive(Default)]
pub struct StubEnclaveClient {
    pub keys: Option<Result<GetEnclaveKeysResponse, EnclaveClientError>>,
    pub match_result: Option<Result<MatchResponse, EnclaveClientError>>,
    pub expected_sealed_payload: Option<Vec<u8>>,
}

#[async_trait]
impl EnclaveClient for StubEnclaveClient {
    async fn health(&self) -> Result<(), EnclaveClientError> {
        Ok(())
    }

    async fn get_enclave_keys(&self) -> Result<GetEnclaveKeysResponse, EnclaveClientError> {
        self.keys
            .clone()
            .expect("route requested enclave keys but the stub was not configured to answer")
    }

    async fn run_match(&self, request: MatchRequest) -> Result<MatchResponse, EnclaveClientError> {
        if let Some(expected) = &self.expected_sealed_payload {
            assert_eq!(&request.sealed_payload, expected);
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

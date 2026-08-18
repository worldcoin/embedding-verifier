//! Shared test doubles for the HTTP API.

use std::sync::Arc;

use async_trait::async_trait;
use enclave_types::{GetEnclaveKeysResponse, MatchRequest, MatchResponse};

use crate::enclave::{EnclaveClient, EnclaveClientError};
use crate::types::{AppState, Environment};

/// An [`EnclaveClient`] answering from fixed results.
///
/// Unconfigured operations panic, so a route calling the wrong one fails loudly.
pub struct StubEnclaveClient {
    keys: Option<Result<GetEnclaveKeysResponse, EnclaveClientError>>,
    match_result: Option<Result<MatchResponse, EnclaveClientError>>,
    expected_sealed_payload: Option<Vec<u8>>,
}

impl StubEnclaveClient {
    /// Answers key requests with `keys`.
    #[must_use]
    pub const fn returning_keys(keys: GetEnclaveKeysResponse) -> Self {
        Self {
            keys: Some(Ok(keys)),
            match_result: None,
            expected_sealed_payload: None,
        }
    }

    /// Answers match requests with `result`.
    #[must_use]
    pub const fn returning_match(result: Result<MatchResponse, EnclaveClientError>) -> Self {
        Self {
            keys: None,
            match_result: Some(result),
            expected_sealed_payload: None,
        }
    }

    /// Fails every operation with `error`.
    #[must_use]
    pub fn failing(error: EnclaveClientError) -> Self {
        Self {
            keys: Some(Err(error.clone())),
            match_result: Some(Err(error)),
            expected_sealed_payload: None,
        }
    }

    /// Asserts the route forwards exactly `payload` to the enclave.
    #[must_use]
    pub fn expecting_sealed_payload(mut self, payload: &[u8]) -> Self {
        self.expected_sealed_payload = Some(payload.to_vec());
        self
    }
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

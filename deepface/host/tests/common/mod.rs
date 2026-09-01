//! Test doubles shared across the host's integration tests.

use std::sync::Arc;

use async_trait::async_trait;
use deepface_host::challenge_store::{
    ChallengeId, ChallengeStore, InMemoryChallengeStore, StoreError,
};
use deepface_host::enclave::{EnclaveClient, EnclaveClientError};
use deepface_host::{AppState, Environment};
use deepface_types::{MatchRequest, MatchResponse};

/// An [`EnclaveClient`] answering from fixed results.
///
/// Unconfigured operations panic, so a route asking for the wrong key fails loudly.
#[derive(Default)]
pub struct StubEnclaveClient {
    pub encryption_key: Option<Result<Vec<u8>, EnclaveClientError>>,
    pub signing_key: Option<Result<Vec<u8>, EnclaveClientError>>,
    pub match_result: Option<Result<MatchResponse, EnclaveClientError>>,
    /// Asserted against the sealed body the route forwards, if set.
    pub expected_body: Option<Vec<u8>>,
    /// Asserted against the stored challenge blob the route forwards, if set.
    pub expected_challenge: Option<Vec<u8>>,
}

#[async_trait]
impl EnclaveClient for StubEnclaveClient {
    async fn health(&self) -> Result<(), EnclaveClientError> {
        Ok(())
    }

    async fn encryption_key_attestation(&self) -> Result<Vec<u8>, EnclaveClientError> {
        self.encryption_key
            .clone()
            .expect("route asked for the encryption key but the stub was not configured to answer")
    }

    async fn signing_key_attestation(&self) -> Result<Vec<u8>, EnclaveClientError> {
        self.signing_key
            .clone()
            .expect("route asked for the signing key but the stub was not configured to answer")
    }

    async fn run_match(&self, request: MatchRequest) -> Result<MatchResponse, EnclaveClientError> {
        if let Some(expected) = &self.expected_body {
            assert_eq!(&request.body, expected);
        }
        if let Some(expected) = &self.expected_challenge {
            assert_eq!(&request.challenge_ciphertext, expected);
        }

        self.match_result
            .clone()
            .expect("route ran a match but the stub was not configured to answer")
    }
}

/// A [`ChallengeStore`] that fails every call, for pinning that an outage is never a miss.
pub struct FailingChallengeStore {
    pub error: StoreError,
}

#[async_trait]
impl ChallengeStore for FailingChallengeStore {
    async fn put(&self, _ciphertext: Vec<u8>) -> Result<ChallengeId, StoreError> {
        Err(self.error.clone())
    }

    async fn get(&self, _id: &ChallengeId) -> Result<Option<Vec<u8>>, StoreError> {
        Err(self.error.clone())
    }
}

/// Builds an [`AppState`] backed by `client` and a fresh in-memory challenge store.
pub fn state_with(client: StubEnclaveClient) -> AppState {
    state_with_store(client, Arc::new(InMemoryChallengeStore::new()))
}

/// Builds an [`AppState`] with both dependencies chosen explicitly.
pub fn state_with_store(client: StubEnclaveClient, store: Arc<dyn ChallengeStore>) -> AppState {
    AppState::new(Environment::Development, Arc::new(client), store)
}

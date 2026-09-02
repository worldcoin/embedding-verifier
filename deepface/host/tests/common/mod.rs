//! Test doubles shared across the host's integration tests.

use std::sync::Arc;

use async_trait::async_trait;
use deepface_host::challenge_fetcher::{ChallengeSource, FetchError};
use deepface_host::enclave::{EnclaveClient, EnclaveClientError};
use deepface_host::{AppState, Environment};
use deepface_types::{MatchRequest, MatchResponse};

/// An [`EnclaveClient`] answering from fixed results.
///
/// Unconfigured operations panic, so a route asking for the wrong key fails loudly.
#[derive(Default)]
pub struct StubEnclaveClient {
    /// `None` is healthy, so only a test about readiness has to say anything.
    pub health: Option<Result<(), EnclaveClientError>>,
    pub encryption_key: Option<Result<Vec<u8>, EnclaveClientError>>,
    pub signing_key: Option<Result<Vec<u8>, EnclaveClientError>>,
    pub match_result: Option<Result<MatchResponse, EnclaveClientError>>,
    /// Asserted against the sealed body the route forwards, if set.
    pub expected_body: Option<Vec<u8>>,
    /// Asserted against the fetched challenge blob the route forwards, if set.
    pub expected_challenge: Option<Vec<u8>>,
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

/// A [`ChallengeSource`] answering from a fixed result.
///
/// The real fetcher resolves ids against a configured bucket, so a local test server could not be
/// reached; stubbing at this seam is what keeps the route testable.
pub struct StubChallengeSource {
    pub result: Result<Vec<u8>, FetchError>,
}

impl StubChallengeSource {
    pub fn returning(bytes: &[u8]) -> Self {
        Self {
            result: Ok(bytes.to_vec()),
        }
    }

    pub const fn failing(error: FetchError) -> Self {
        Self { result: Err(error) }
    }
}

impl Default for StubChallengeSource {
    fn default() -> Self {
        Self::returning(b"challenge-ciphertext")
    }
}

#[async_trait]
impl ChallengeSource for StubChallengeSource {
    async fn fetch(&self, _id: &str) -> Result<Vec<u8>, FetchError> {
        self.result.clone()
    }
}

/// Builds an [`AppState`] backed by `client` and a challenge source that always succeeds.
pub fn state_with(client: StubEnclaveClient) -> AppState {
    state_with_source(client, StubChallengeSource::default())
}

/// Builds an [`AppState`] with both doubles chosen explicitly.
pub fn state_with_source(client: StubEnclaveClient, source: StubChallengeSource) -> AppState {
    AppState::new(Environment::Development, Arc::new(client), Arc::new(source))
}

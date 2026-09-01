//! Test doubles shared across the host's integration tests.

use std::sync::Arc;

use async_trait::async_trait;
use deepface_host::challenge_fetcher::{ChallengeSource, FetchError};
use deepface_host::enclave::{EnclaveClient, EnclaveClientError};
use deepface_host::key_registry::{
    InMemoryKeyRegistry, KeyRegistry, KeyStatus, RegistryEntry, RegistryError, SigningPublicKey,
};
use deepface_host::{AppState, Environment};
use deepface_types::{MatchRequest, MatchResponse};
use tokio::sync::watch;

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
    /// Asserted against the fetched challenge blob the route forwards, if set.
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

/// A [`KeyRegistry`] that fails every call, for the paths that must not answer `404`.
pub struct UnavailableKeyRegistry;

#[async_trait]
impl KeyRegistry for UnavailableKeyRegistry {
    async fn get(&self, _: SigningPublicKey) -> Result<Option<RegistryEntry>, RegistryError> {
        Err(RegistryError::Unavailable("no route to host".to_string()))
    }

    async fn set(&self, _: &RegistryEntry) -> Result<(), RegistryError> {
        Err(RegistryError::Unavailable("no route to host".to_string()))
    }
}

/// An active row for `public_key`, as registration would have written it.
pub fn active_entry(public_key: SigningPublicKey) -> RegistryEntry {
    RegistryEntry {
        public_key,
        attestation: b"attestation-document".to_vec(),
        pcr0: vec![9; 48],
        valid_from: 1_780_000_000,
        retired_at: None,
        status: KeyStatus::Active,
    }
}

/// Builds an [`AppState`] backed by `client` and a challenge source that always succeeds.
pub fn state_with(client: StubEnclaveClient) -> AppState {
    state_with_source(client, StubChallengeSource::default())
}

/// Builds an [`AppState`] with both doubles chosen explicitly.
pub fn state_with_source(client: StubEnclaveClient, source: StubChallengeSource) -> AppState {
    state_with_registry(client, source, Arc::new(InMemoryKeyRegistry::new()))
}

/// Builds an [`AppState`] over `registry`, with this boot's key already registered.
///
/// A `watch` receiver keeps serving the last value after its sender drops, which is all the
/// state reads.
pub fn state_with_registry(
    client: StubEnclaveClient,
    source: StubChallengeSource,
    registry: Arc<dyn KeyRegistry>,
) -> AppState {
    let (_sender, receiver) = watch::channel(Some(registered_key()));

    AppState::new(
        Environment::Development,
        Arc::new(client),
        Arc::new(source),
        registry,
        receiver,
    )
}

/// Builds an [`AppState`] whose signing key is not in the registry yet.
pub fn state_before_registration(client: StubEnclaveClient) -> AppState {
    let (_sender, receiver) = watch::channel(None);

    AppState::new(
        Environment::Development,
        Arc::new(client),
        Arc::new(StubChallengeSource::default()),
        Arc::new(InMemoryKeyRegistry::new()),
        receiver,
    )
}

/// The key the test state reports as registered.
pub fn registered_key() -> SigningPublicKey {
    SigningPublicKey::from_bytes([7; 32])
}

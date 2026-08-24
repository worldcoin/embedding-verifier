//! Client boundary between the host and enclave.

use std::time::Duration;

use async_trait::async_trait;
use deepface_types::{MatchRequest, MatchResponse};
use enclave_types::{EnclaveError, GetEncryptionKeyRequest, GetSigningKeyRequest, HealthRequest};
use pontifex::Request;
use pontifex::client::ConnectionDetails;
use tokio::time::timeout;

const CONTROL_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
// Match requests can carry large payloads and require expensive computation.
const MATCH_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Failures while calling an enclave operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnclaveClientError {
    /// The Pontifex connection or wire operation failed.
    Transport(String),
    /// The enclave returned a structured operation error.
    Operation(EnclaveError),
    /// The enclave did not answer within the API's request deadline.
    Timeout,
}

/// Operations the host requires from the enclave.
#[async_trait]
pub trait EnclaveClient: Send + Sync {
    /// Checks whether the enclave process is reachable and ready.
    async fn health(&self) -> Result<(), EnclaveClientError>;

    /// Fetches the attestation for the enclave's boot-scoped encryption key.
    async fn encryption_key_attestation(&self) -> Result<Vec<u8>, EnclaveClientError>;

    /// Fetches the attestation for the enclave's boot-scoped signing key.
    async fn signing_key_attestation(&self) -> Result<Vec<u8>, EnclaveClientError>;

    /// Runs a match inside the enclave.
    async fn run_match(&self, request: MatchRequest) -> Result<MatchResponse, EnclaveClientError>;
}

/// Pontifex-backed enclave client.
#[derive(Debug, Clone, Copy)]
pub struct PontifexEnclaveClient {
    connection: ConnectionDetails,
}

impl PontifexEnclaveClient {
    /// Creates a client for the provided enclave CID and Pontifex port.
    #[must_use]
    pub const fn new(cid: u32, port: u32) -> Self {
        Self {
            connection: ConnectionDetails::new(cid, port),
        }
    }

    /// Sends `request` under `deadline`, flattening the timeout, transport and operation layers.
    async fn call<R, T>(&self, request: R, deadline: Duration) -> Result<T, EnclaveClientError>
    where
        R: Request<Response = Result<T, EnclaveError>> + Sync,
    {
        timeout(deadline, pontifex::client::send(self.connection, &request))
            .await
            .map_err(|_| EnclaveClientError::Timeout)?
            .map_err(|error| EnclaveClientError::Transport(error.to_string()))?
            .map_err(EnclaveClientError::Operation)
    }
}

#[async_trait]
impl EnclaveClient for PontifexEnclaveClient {
    async fn health(&self) -> Result<(), EnclaveClientError> {
        self.call(HealthRequest, CONTROL_REQUEST_TIMEOUT).await
    }

    async fn encryption_key_attestation(&self) -> Result<Vec<u8>, EnclaveClientError> {
        self.call(GetEncryptionKeyRequest, CONTROL_REQUEST_TIMEOUT)
            .await
            .map(|attestation| attestation.document)
    }

    async fn signing_key_attestation(&self) -> Result<Vec<u8>, EnclaveClientError> {
        self.call(GetSigningKeyRequest, CONTROL_REQUEST_TIMEOUT)
            .await
            .map(|attestation| attestation.document)
    }

    async fn run_match(&self, request: MatchRequest) -> Result<MatchResponse, EnclaveClientError> {
        self.call(request, MATCH_REQUEST_TIMEOUT).await
    }
}

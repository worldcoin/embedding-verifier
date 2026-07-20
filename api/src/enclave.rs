//! Client boundary between the HTTP API and secure enclave.

use std::time::Duration;

use async_trait::async_trait;
use enclave_types::{EnclaveError, GetTransitKeyRequest, GetTransitKeyResponse, HealthRequest};
use pontifex::client::ConnectionDetails;
use tokio::time::timeout;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Failures while calling a secure-enclave operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnclaveClientError {
    /// The Pontifex connection or wire operation failed.
    Transport(String),
    /// The enclave returned a structured operation error.
    Operation(EnclaveError),
    /// The enclave did not answer within the API's request deadline.
    Timeout,
}

/// Operations the HTTP API requires from the secure enclave.
#[async_trait]
pub trait EnclaveClient: Send + Sync {
    /// Checks whether the enclave process is reachable and ready.
    async fn health(&self) -> Result<(), EnclaveClientError>;

    /// Fetches an attestation document containing the enclave's transit public key.
    async fn get_transit_key(&self) -> Result<GetTransitKeyResponse, EnclaveClientError>;
}

/// Pontifex-backed secure-enclave client.
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
}

#[async_trait]
impl EnclaveClient for PontifexEnclaveClient {
    async fn health(&self) -> Result<(), EnclaveClientError> {
        let response = timeout(
            REQUEST_TIMEOUT,
            pontifex::client::send(self.connection, &HealthRequest),
        )
        .await
        .map_err(|_| EnclaveClientError::Timeout)?
        .map_err(|error| EnclaveClientError::Transport(error.to_string()))?;

        response.map_err(EnclaveClientError::Operation)
    }

    async fn get_transit_key(&self) -> Result<GetTransitKeyResponse, EnclaveClientError> {
        let response = timeout(
            REQUEST_TIMEOUT,
            pontifex::client::send(self.connection, &GetTransitKeyRequest),
        )
        .await
        .map_err(|_| EnclaveClientError::Timeout)?
        .map_err(|error| EnclaveClientError::Transport(error.to_string()))?;

        response.map_err(EnclaveClientError::Operation)
    }
}

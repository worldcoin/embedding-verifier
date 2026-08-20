//! HTTP client for the embedding verifier host.

use std::time::SystemTime;

use serde::Deserialize;

use crypto::nitro::{EnclaveAttestationError, EnclaveAttestationVerifier, VerifiedAttestation};
use crypto::sealed_channel::Requester;

use crate::config::Config;

/// Path of the assignment endpoint.
const ASSIGNMENT_PATH: &str = "/v1/enclave-assignment";

/// Failures while calling the host.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The HTTP client could not be constructed.
    #[error("failed to build HTTP client: {0}")]
    Transport(#[source] reqwest::Error),

    /// The request failed, timed out, or the body could not be read.
    #[error("request to the host failed: {0}")]
    Request(#[source] reqwest::Error),

    /// The host answered with a non-success status.
    #[error("host returned HTTP {0}")]
    Status(u16),

    /// The response was not the JSON the endpoint is specified to return.
    #[error("response was not valid JSON: {0}")]
    MalformedResponse(#[source] reqwest::Error),

    /// An attestation document did not verify.
    #[error(transparent)]
    Attestation(#[from] EnclaveAttestationError),

    /// The attested encryption public key was absent or not exactly 32 bytes.
    #[error("attested encryption public key was invalid")]
    InvalidEncryptionKey,
}

/// The host's assignment response.
#[derive(Debug, Deserialize)]
struct EnclaveAssignmentResponse {
    attestation: String,
}

/// An assignment whose attestation verified and whose encryption key is ready for sealing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAssignment {
    /// Metadata read from the signed attestation document.
    pub attestation: VerifiedAttestation,
    /// The verified requester handle for sealing to this enclave boot.
    pub requester: Requester,
}

/// Calls the face verifier host and verifies the attestation documents it relays.
///
/// Nothing is returned until the enclave that produced it has been verified, so callers
/// cannot accidentally use an unattested key.
#[derive(Debug)]
pub struct FaceVerifierClient {
    config: Config,
    http: reqwest::Client,
    verifier: EnclaveAttestationVerifier,
}

impl FaceVerifierClient {
    /// Builds a client from `config`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the HTTP client cannot be built.
    pub fn new(config: Config) -> Result<Self, ClientError> {
        let http = reqwest::Client::builder()
            .connect_timeout(config.connect_timeout())
            .timeout(config.request_timeout())
            .build()
            .map_err(ClientError::Transport)?;

        Ok(Self {
            verifier: config.verifier(),
            http,
            config,
        })
    }

    /// Requests an assignment and returns it only if its attestation verifies.
    ///
    /// No retry: the endpoint costs an NSM attestation per call, and the spec already has the
    /// authenticator re-assigning when a match fails.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the request fails, the host answers with an error status,
    /// or the attestation document does not verify.
    pub async fn request_assignment(
        &self,
        now: SystemTime,
    ) -> Result<VerifiedAssignment, ClientError> {
        let url = format!(
            "{}{ASSIGNMENT_PATH}",
            self.config.host_url().as_str().trim_end_matches('/')
        );
        let response = self
            .http
            .post(url)
            .send()
            .await
            .map_err(ClientError::Request)?;

        let status = response.status();
        if !status.is_success() {
            return Err(ClientError::Status(status.as_u16()));
        }

        let assignment: EnclaveAssignmentResponse = response
            .json()
            .await
            .map_err(ClientError::MalformedResponse)?;

        let attestation = self
            .verifier
            .verify_base64(assignment.attestation.trim(), now)?;
        let requester = Requester::from_attestation(&attestation.enclave_public_key)
            .map_err(|_| ClientError::InvalidEncryptionKey)?;

        Ok(VerifiedAssignment {
            attestation,
            requester,
        })
    }
}

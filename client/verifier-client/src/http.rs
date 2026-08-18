//! HTTP client for the host's enclave-assignment endpoint.

use std::time::{Duration, SystemTime};

use serde::Deserialize;

use crate::nitro::{EnclaveAttestationError, EnclaveAttestationVerifier, VerifiedAttestation};

/// Path of the assignment endpoint on the host.
const ASSIGNMENT_PATH: &str = "/v1/enclave-assignment";

/// How long the whole request may take, connection included.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// How long establishing the connection may take.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest assignment body we will read.
///
/// An attestation document is a few kB; anything approaching this is a malfunctioning or
/// hostile host, and reading it would be the start of a memory-exhaustion problem.
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// Failures while obtaining an enclave assignment.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The base URL could not be used to build the endpoint URL.
    #[error("invalid base URL: {0}")]
    InvalidBaseUrl(String),

    /// The HTTP client could not be constructed.
    #[error("failed to build HTTP client: {0}")]
    Transport(#[source] reqwest::Error),

    /// The request failed, timed out, or the body could not be read.
    #[error("request to the assignment endpoint failed: {0}")]
    Request(#[source] reqwest::Error),

    /// The host answered with a non-success status.
    #[error("assignment endpoint returned HTTP {status}")]
    Status {
        /// The status the host returned.
        status: u16,
    },

    /// The response body was larger than [`MAX_RESPONSE_BYTES`].
    #[error("assignment response is {length} bytes, over the {MAX_RESPONSE_BYTES} byte limit")]
    ResponseTooLarge {
        /// Length the host advertised.
        length: u64,
    },

    /// The response was not the JSON this endpoint is specified to return.
    #[error("assignment response was not valid JSON: {0}")]
    MalformedResponse(#[source] reqwest::Error),

    /// The attestation document did not verify.
    #[error(transparent)]
    Attestation(#[from] EnclaveAttestationError),
}

/// The host's assignment response.
///
/// The document is the whole payload: the enclave's identity and expiry are read from it
/// after verification, never from fields the untrusted host could set.
#[derive(Debug, Deserialize)]
struct EnclaveAssignmentResponse {
    attestation: String,
}

/// Requests enclave assignments and verifies the attestation documents they carry.
#[derive(Debug)]
pub struct Client {
    http: reqwest::Client,
    assignment_url: String,
    verifier: EnclaveAttestationVerifier,
}

impl Client {
    /// Builds a client against `base_url`, e.g. `http://localhost:8000`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the URL is unusable or the HTTP client cannot be built.
    pub fn new(base_url: &str, verifier: EnclaveAttestationVerifier) -> Result<Self, ClientError> {
        let trimmed = base_url.trim_end_matches('/');
        if trimmed.is_empty() {
            return Err(ClientError::InvalidBaseUrl("base URL is empty".to_string()));
        }

        let http = reqwest::Client::builder()
            .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .build()
            .map_err(ClientError::Transport)?;

        Ok(Self {
            http,
            assignment_url: format!("{trimmed}{ASSIGNMENT_PATH}"),
            verifier,
        })
    }

    /// Requests an assignment and returns it only if its attestation verifies.
    ///
    /// There is no retry here on purpose. The caller decides whether to retry, and the spec
    /// already has the authenticator re-assigning when a match fails, so retrying inside this
    /// call would multiply requests onto an endpoint that costs an NSM attestation each time.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the request fails, the host answers with an error status,
    /// or the attestation document does not verify.
    pub async fn request_assignment(
        &self,
        now: SystemTime,
    ) -> Result<VerifiedAttestation, ClientError> {
        let response = self
            .http
            .post(&self.assignment_url)
            .send()
            .await
            .map_err(ClientError::Request)?;

        let status = response.status();
        if !status.is_success() {
            return Err(ClientError::Status {
                status: status.as_u16(),
            });
        }

        // Reject an oversized body before reading it. A host that omits Content-Length is
        // still bounded, by the total request timeout above.
        if let Some(length) = response.content_length()
            && length > MAX_RESPONSE_BYTES
        {
            return Err(ClientError::ResponseTooLarge { length });
        }

        let assignment: EnclaveAssignmentResponse = response
            .json()
            .await
            .map_err(ClientError::MalformedResponse)?;

        Ok(self
            .verifier
            .verify_base64(assignment.attestation.trim(), now)?)
    }
}

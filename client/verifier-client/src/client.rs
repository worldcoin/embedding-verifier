//! HTTP client for the embedding verifier host.

use std::time::SystemTime;

use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::config::Config;
use crate::nitro::{EnclaveAttestationError, EnclaveAttestationVerifier, VerifiedAttestation};

/// Path of the assignment endpoint.
const ASSIGNMENT_PATH: &str = "/v1/enclave-assignment";

/// Failures while calling the host.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The HTTP client could not be constructed.
    #[error("failed to build HTTP client: {0}")]
    Transport(#[source] reqwest::Error),

    /// The request failed, timed out, or the body could not be read.
    #[error("request to {path} failed: {source}")]
    Request {
        /// Path that was requested.
        path: &'static str,
        /// Underlying failure.
        #[source]
        source: reqwest::Error,
    },

    /// The host answered with a non-success status.
    #[error("{path} returned HTTP {status}")]
    Status {
        /// Path that was requested.
        path: &'static str,
        /// The status the host returned.
        status: u16,
    },

    /// The response body exceeded [`Config::max_response_bytes`].
    #[error("{path} response is {length} bytes, over the {limit} byte limit")]
    ResponseTooLarge {
        /// Path that was requested.
        path: &'static str,
        /// Length the host advertised.
        length: u64,
        /// Configured limit.
        limit: u64,
    },

    /// The response was not the JSON the endpoint is specified to return.
    #[error("{path} response was not valid JSON: {source}")]
    MalformedResponse {
        /// Path that was requested.
        path: &'static str,
        /// Underlying failure.
        #[source]
        source: reqwest::Error,
    },

    /// An attestation document did not verify.
    #[error(transparent)]
    Attestation(#[from] EnclaveAttestationError),
}

/// The host's assignment response.
#[derive(Debug, Deserialize)]
struct EnclaveAssignmentResponse {
    attestation: String,
}

/// Calls the host and verifies the attestation documents it relays.
#[derive(Debug)]
pub struct Client {
    /// The configuration this client was built from.
    pub config: Config,
    http: reqwest::Client,
    verifier: EnclaveAttestationVerifier,
}

impl Client {
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
    ) -> Result<VerifiedAttestation, ClientError> {
        let assignment: EnclaveAssignmentResponse = self.post_json(ASSIGNMENT_PATH).await?;

        Ok(self
            .verifier
            .verify_base64(assignment.attestation.trim(), now)?)
    }

    /// POSTs to `path` with no body and decodes the JSON response.
    ///
    /// Shared by every operation so status handling and the size cap cannot diverge.
    async fn post_json<T: DeserializeOwned>(&self, path: &'static str) -> Result<T, ClientError> {
        let response = self
            .http
            .post(format!(
                "{}{path}",
                self.config.host_url().as_str().trim_end_matches('/')
            ))
            .send()
            .await
            .map_err(|source| ClientError::Request { path, source })?;

        let status = response.status();
        if !status.is_success() {
            return Err(ClientError::Status {
                path,
                status: status.as_u16(),
            });
        }

        // A host that omits Content-Length is still bounded by the request timeout.
        if let Some(length) = response.content_length()
            && length > self.config.max_response_bytes()
        {
            return Err(ClientError::ResponseTooLarge {
                path,
                length,
                limit: self.config.max_response_bytes(),
            });
        }

        response
            .json()
            .await
            .map_err(|source| ClientError::MalformedResponse { path, source })
    }
}

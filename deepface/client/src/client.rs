//! HTTP client for the embedding verifier host.

use std::time::SystemTime;

use base64::{Engine as _, engine::general_purpose::STANDARD};

use attested_channel::channel::{ChannelError, Requester, SealedResponse, UnwrapErr};
use attested_channel::nitro::{
    EnclaveAttestationError, EnclaveAttestationVerifier, VerifiedAttestation,
};
use deepface_api_types::{
    ApiErrorResponse, EnclaveAssignmentResponse, MatchRequestBody, MatchResponseBody,
};
use deepface_protocol::match_token::{self, EdDSAPublicKey};
use deepface_protocol::messages::{MatchInputs, MatchResult};
use getrandom::SysRng;

use crate::config::Config;

/// Path of the assignment endpoint.
const ASSIGNMENT_PATH: &str = "/v1/enclave-assignment";

/// Path of the match endpoint.
const MATCHES_PATH: &str = "/v1/matches";

/// Error code the host uses for a request that did not open.
const REASSIGN_REQUIRED: &str = "reassign_required";

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

    /// The host answered with an error envelope.
    #[error("host returned HTTP {status} ({code})")]
    Api {
        /// HTTP status the host chose.
        status: u16,
        /// Machine-readable code from the envelope.
        code: String,
        /// Whether the host says the request may be retried.
        allow_retry: bool,
    },

    /// The assignment is stale: re-assign, re-seal, and retry once.
    #[error("the request was not sealed to the enclave's current key; re-assign and retry once")]
    ReassignRequired,

    /// Sealing the request or opening the response failed.
    #[error("sealed channel failure: {0:?}")]
    Channel(ChannelError),

    /// The response ciphertext was not valid base64.
    #[error("response ciphertext was not valid base64")]
    MalformedCiphertext,

    /// The sealed plaintext was not a match result.
    #[error("sealed response was not a match result")]
    MalformedResult,

    /// The attested signing public key was not a valid `BabyJubJub` point.
    #[error("attested signing public key was invalid")]
    InvalidSigningKey,

    /// The statement did not verify under the attested signing key.
    #[error("match statement did not verify under the attested signing key")]
    StatementInvalid,
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
            // Replays the ALB's affinity cookie, so the match reaches the enclave that was assigned.
            .cookie_store(true)
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

    /// Runs a match against the enclave `assignment` names.
    ///
    /// [`MatchResult::Failed`] is a normal return, not an error. A statement is verified against the
    /// attested signing key first; call [`match_token::verify`] again to read its claims.
    ///
    /// The caller supplies all three frames in `inputs`, challenge image included: it downloads
    /// that frame from the RP itself, so nothing here needs to know where the RP keeps it.
    ///
    /// # Errors
    ///
    /// [`ClientError::ReassignRequired`] on a stale assignment — retry once with a fresh one.
    pub async fn request_match(
        &self,
        assignment: &VerifiedAssignment,
        inputs: &MatchInputs,
        now: SystemTime,
    ) -> Result<MatchResult, ClientError> {
        let plaintext = inputs.to_cbor().map_err(|_| ClientError::MalformedResult)?;
        let (sealed, opener) = assignment
            .requester
            .seal(&plaintext, &mut UnwrapErr(SysRng))
            .map_err(ClientError::Channel)?;

        let url = format!(
            "{}{MATCHES_PATH}",
            self.config.host_url().as_str().trim_end_matches('/')
        );
        let response = self
            .http
            .post(url)
            .json(&MatchRequestBody {
                ciphertext: STANDARD.encode(sealed.into_bytes()),
            })
            .send()
            .await
            .map_err(ClientError::Request)?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.ok();
            return Err(Self::api_error(status.as_u16(), body.as_deref()));
        }

        let body: MatchResponseBody = response
            .json()
            .await
            .map_err(ClientError::MalformedResponse)?;

        let ciphertext = STANDARD
            .decode(body.response_ciphertext.trim())
            .map_err(|_| ClientError::MalformedCiphertext)?;
        let plaintext = opener
            .open(&SealedResponse::from_bytes(ciphertext))
            .map_err(ClientError::Channel)?;
        let result =
            MatchResult::from_cbor(&plaintext).map_err(|_| ClientError::MalformedResult)?;

        // Only a statement needs the key, so a rejection skips the attestation entirely.
        if let MatchResult::Success(statement) = &result {
            // Verified as of `now`: the document came sealed from the enclave that just answered.
            let attested = self
                .verifier
                .verify(&statement.signing_key_attestation, now)?;
            let signing_key = <[u8; 32]>::try_from(attested.enclave_public_key.as_slice())
                .map_err(|_| ClientError::InvalidSigningKey)
                .and_then(|bytes| {
                    EdDSAPublicKey::from_compressed_bytes(bytes)
                        .map_err(|_| ClientError::InvalidSigningKey)
                })?;

            match_token::verify(&statement.token, &signing_key)
                .map_err(|_| ClientError::StatementInvalid)?;
        }

        Ok(result)
    }

    /// Classifies a non-success response, reading the error envelope when there is one.
    fn api_error(status: u16, body: Option<&str>) -> ClientError {
        let Some(envelope) =
            body.and_then(|body| serde_json::from_str::<ApiErrorResponse>(body).ok())
        else {
            return ClientError::Status(status);
        };

        if envelope.error.code == REASSIGN_REQUIRED {
            return ClientError::ReassignRequired;
        }

        ClientError::Api {
            status,
            code: envelope.error.code,
            allow_retry: envelope.allow_retry,
        }
    }
}

//! HTTP client for the embedding verifier host.

use base64::{Engine as _, engine::general_purpose::STANDARD};

use flamingo_verifier_api_types::{
    ApiErrorResponse, EnclaveAssignmentResponse, MatchRequestBody, MatchResponseBody,
};
use flamingo_verifier_protocol::match_token::{self, EdDSAPublicKey};
use flamingo_verifier_sealed_types::{MATCH_CHANNEL_DOMAIN, MatchInputs, MatchResult};
use pontifex::attestation::{VerifiedAttestation, Verifier};
use pontifex::{ChannelConsumer, ChannelDomain};

use crate::config::Config;
use crate::error::Error;

/// Path of the assignment endpoint.
const ASSIGNMENT_PATH: &str = "/v1/enclave-assignment";

/// Path of the match endpoint.
const MATCHES_PATH: &str = "/v1/matches";

/// Error code the host uses for a request that did not open.
const REASSIGN_REQUIRED: &str = "reassign_required";

/// An assignment whose attestation verified and whose encryption key is ready for sealing.
#[derive(Debug, Clone)]
pub struct VerifiedAssignment {
    /// Metadata read from the signed attestation document.
    attestation: VerifiedAttestation,
    consumer: ChannelConsumer,
}

impl VerifiedAssignment {
    /// Metadata from the verified channel-key attestation.
    #[must_use]
    pub const fn attestation(&self) -> &VerifiedAttestation {
        &self.attestation
    }

    /// The channel consumer bound to this assignment's verified key.
    #[must_use]
    pub const fn consumer(&self) -> &ChannelConsumer {
        &self.consumer
    }
}

// TODO: Rename FaceVerifierClient to FlamingoVerifierClient.
/// Calls the face verifier host and verifies the attestation documents it relays.
///
/// Nothing is returned until the enclave that produced it has been verified, so callers
/// cannot accidentally use an unattested key.
#[derive(Debug)]
pub struct FaceVerifierClient {
    config: Config,
    http: reqwest::Client,
    verifier: Verifier,
}

impl FaceVerifierClient {
    /// Builds a client from `config`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the configuration is invalid or the HTTP client cannot be built.
    pub fn new(config: Config) -> Result<Self, Error> {
        let http = reqwest::Client::builder()
            // Replays the ALB's affinity cookie, so the match reaches the enclave that was assigned.
            .cookie_store(true)
            .connect_timeout(config.connect_timeout())
            .timeout(config.request_timeout())
            .build()
            .map_err(Error::Transport)?;

        Ok(Self {
            verifier: config.verifier()?,
            http,
            config,
        })
    }

    /// Requests an assignment and returns it only if its attestation verifies.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the request fails, the host answers with an error status,
    /// or the attestation document does not verify.
    pub async fn request_assignment(&self) -> Result<VerifiedAssignment, Error> {
        let url = format!(
            "{}{ASSIGNMENT_PATH}",
            self.config.host_url().as_str().trim_end_matches('/')
        );
        let response = self.http.post(url).send().await.map_err(Error::Request)?;

        let status = response.status();
        if !status.is_success() {
            return Err(Error::Status(status.as_u16()));
        }

        let assignment: EnclaveAssignmentResponse =
            response.json().await.map_err(Error::MalformedResponse)?;

        let document = STANDARD
            .decode(&assignment.attestation)
            .map_err(|_| Error::MalformedAssignment)?;
        let public_key = STANDARD
            .decode(&assignment.public_key)
            .map_err(|_| Error::MalformedAssignment)?;
        let (consumer, attestation) = ChannelConsumer::from_attestation(
            ChannelDomain::new(MATCH_CHANNEL_DOMAIN),
            &self.verifier,
            &document,
            &public_key,
        )
        .map_err(Error::Channel)?;

        Ok(VerifiedAssignment {
            attestation,
            consumer,
        })
    }

    /// Runs a match against the enclave `assignment` names.
    ///
    /// [`MatchResult::Failed`] is a normal return, not an error. A statement is verified against the
    /// attested signing key first; call [`match_token::verify`] again to read its claims.
    ///
    /// The caller supplies all three frames in `inputs`, challenge image included.
    ///
    /// # Errors
    ///
    /// [`Error::ReassignRequired`] on a stale assignment — retry once with a fresh one.
    pub async fn request_match(
        &self,
        assignment: &VerifiedAssignment,
        inputs: &MatchInputs,
    ) -> Result<MatchResult, Error> {
        self.request_match_with_consumer(assignment.consumer(), inputs)
            .await
    }

    async fn request_match_with_consumer(
        &self,
        consumer: &ChannelConsumer,
        inputs: &MatchInputs,
    ) -> Result<MatchResult, Error> {
        let plaintext = inputs.to_cbor().map_err(|_| Error::MalformedResult)?;
        let (sealed, opener) = consumer
            .seal_to_enclave(&plaintext)
            .map_err(Error::Channel)?;

        let url = format!(
            "{}{MATCHES_PATH}",
            self.config.host_url().as_str().trim_end_matches('/')
        );
        let response = self
            .http
            .post(url)
            .json(&MatchRequestBody {
                ciphertext: STANDARD.encode(sealed),
            })
            .send()
            .await
            .map_err(Error::Request)?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.ok();
            return Err(Self::api_error(status.as_u16(), body.as_deref()));
        }

        let body: MatchResponseBody = response.json().await.map_err(Error::MalformedResponse)?;

        let ciphertext = STANDARD
            .decode(body.response_ciphertext.trim())
            .map_err(|_| Error::MalformedCiphertext)?;
        let plaintext = opener
            .open_from_enclave(&ciphertext)
            .map_err(Error::Channel)?;
        let result =
            MatchResult::from_padded_cbor(&plaintext).map_err(|_| Error::MalformedResult)?;

        // Only a statement needs the key, so a rejection skips the attestation entirely.
        if let MatchResult::Success(statement) = &result {
            // Response encryption alone does not authenticate the signing key.
            let attested = self
                .verifier
                .verify_attestation_document(&statement.signing_key_attestation)?;
            let signing_key = <[u8; 32]>::try_from(
                attested
                    .document()
                    .public_key
                    .as_ref()
                    .ok_or(Error::InvalidSigningKey)?
                    .as_slice(),
            )
            .map_err(|_| Error::InvalidSigningKey)
            .and_then(|bytes| {
                EdDSAPublicKey::from_compressed_bytes(bytes).map_err(|_| Error::InvalidSigningKey)
            })?;

            match_token::verify(&statement.token, &signing_key)
                .map_err(|_| Error::StatementInvalid)?;
        }

        Ok(result)
    }

    /// Classifies a non-success response, reading the error envelope when there is one.
    fn api_error(status: u16, body: Option<&str>) -> Error {
        let Some(envelope) =
            body.and_then(|body| serde_json::from_str::<ApiErrorResponse>(body).ok())
        else {
            return Error::Status(status);
        };

        if envelope.error.code == REASSIGN_REQUIRED {
            return Error::ReassignRequired;
        }

        Error::Api {
            status,
            code: envelope.error.code,
            allow_retry: envelope.allow_retry,
        }
    }
}

#[cfg(test)]
#[path = "tests/matches.rs"]
mod tests;

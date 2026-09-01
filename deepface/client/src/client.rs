//! HTTP client for the embedding verifier host.

use std::time::SystemTime;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use attested_channel::channel::{ChannelError, Requester, SealedResponse, UnwrapErr};
use attested_channel::nitro::{
    EnclaveAttestationError, EnclaveAttestationVerifier, VerifiedAttestation,
};
use deepface_protocol::match_token::{self, EdDSAPublicKey};
use deepface_protocol::messages::{MatchInputs, MatchResult};
use getrandom::SysRng;

use crate::config::Config;

/// Path of the assignment endpoint.
const ASSIGNMENT_PATH: &str = "/v1/enclave-assignment";

/// Path of the match endpoint.
const MATCHES_PATH: &str = "/v1/matches";

/// Path prefix of the signing-key lookup.
const SIGNING_KEYS_PATH: &str = "/v1/signing-keys";

/// Length of a compressed `BabyJubJub` signing public key.
const SIGNING_PUBLIC_KEY_LEN: usize = 32;

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

    /// The key to look up was not 32 bytes of hex.
    #[error("signing public key was not 32 bytes of hex")]
    InvalidSigningKeyId,

    /// The row's document attests a different key than the one asked for. An untrusted host
    /// answering one lookup with another key's attestation is the whole reason to check.
    #[error("registry answered for a different signing key than the one requested")]
    SigningKeyMismatch,
}

/// The host's error envelope.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiErrorBody {
    allow_retry: bool,
    error: ApiErrorCode,
}

/// The `error` object inside [`ApiErrorBody`].
#[derive(Debug, Deserialize)]
struct ApiErrorCode {
    code: String,
}

/// A match request, as the host reads it.
#[derive(Debug, Serialize)]
struct MatchRequestBody {
    challenge_image_id: String,
    ciphertext: String,
}

/// The host's match response.
#[derive(Debug, Deserialize)]
struct MatchResponseBody {
    response_ciphertext: String,
    key_attestation: String,
}

/// The host's assignment response.
#[derive(Debug, Deserialize)]
struct EnclaveAssignmentResponse {
    attestation: String,
}

/// Where a `Signing Key` stands, as the registry reports it.
///
/// The three answer different questions about a statement the key signed and MUST NOT be
/// collapsed into one another; [`VerifiedSigningKey::accepts_statement_signed_at`] applies them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    /// The enclave is running. Statements it signs are acceptable.
    Active,
    /// The enclave shut down normally. Statements signed before `retired_at` stay acceptable.
    Retired,
    /// The enclave or its image was withdrawn. Every statement this key signed is invalid.
    Revoked,
}

/// The host's signing-key response.
#[derive(Debug, Deserialize)]
struct SigningKeyResponseBody {
    attestation: String,
    valid_from: u64,
    retired_at: Option<u64>,
    status: KeyStatus,
}

/// A registry row whose attestation verified and which is ready to check a statement against.
///
/// `pcr0` is deliberately absent: the row reports one, but the verified document is the only
/// account of what ran, so measurements are read from [`Self::attestation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSigningKey {
    /// Metadata read from the signed attestation document.
    pub attestation: VerifiedAttestation,
    /// The attested key, ready for [`match_token::verify`].
    pub signing_key: EdDSAPublicKey,
    /// When the key was attested, in seconds since the Unix epoch.
    pub valid_from: u64,
    /// When the enclave shut down, if it has.
    pub retired_at: Option<u64>,
    /// Validity state.
    pub status: KeyStatus,
}

impl VerifiedSigningKey {
    /// Whether a statement signed at `signed_at` is acceptable under this row.
    ///
    /// Retirement is not revocation: an enclave that shut down normally leaves everything it
    /// signed beforehand standing, while a revoked key invalidates its statements retroactively.
    #[must_use]
    pub const fn accepts_statement_signed_at(&self, signed_at: u64) -> bool {
        accepts_statement(self.status, self.valid_from, self.retired_at, signed_at)
    }
}

/// The validity rule on its own, so it can be exercised without enclave key material.
const fn accepts_statement(
    status: KeyStatus,
    valid_from: u64,
    retired_at: Option<u64>,
    signed_at: u64,
) -> bool {
    if signed_at < valid_from {
        return false;
    }

    match status {
        KeyStatus::Active => true,
        KeyStatus::Revoked => false,
        // A row that says retired without saying when cannot place the statement, and a guess
        // here would accept one signed after the enclave was gone.
        KeyStatus::Retired => match retired_at {
            Some(at) => signed_at < at,
            None => false,
        },
    }
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

    /// Runs a match against the enclave `assignment` names.
    ///
    /// [`MatchResult::Failed`] is a normal return, not an error. A statement is verified against the
    /// attested signing key first; call [`match_token::verify`] again to read its claims.
    ///
    /// The object at `challenge_image_id` must be encrypted under the key and IV in `inputs`.
    ///
    /// # Errors
    ///
    /// [`ClientError::ReassignRequired`] on a stale assignment — retry once with a fresh one.
    pub async fn request_match(
        &self,
        assignment: &VerifiedAssignment,
        inputs: &MatchInputs,
        challenge_image_id: &str,
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
                challenge_image_id: challenge_image_id.to_owned(),
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
        if let MatchResult::Success(token) = &result {
            let attested = self
                .verifier
                .verify_base64(body.key_attestation.trim(), now)?;
            let signing_key = <[u8; 32]>::try_from(attested.enclave_public_key.as_slice())
                .map_err(|_| ClientError::InvalidSigningKey)
                .and_then(|bytes| {
                    EdDSAPublicKey::from_compressed_bytes(bytes)
                        .map_err(|_| ClientError::InvalidSigningKey)
                })?;

            match_token::verify(token, &signing_key).map_err(|_| ClientError::StatementInvalid)?;
        }

        Ok(result)
    }

    /// Looks up one signing key and returns it only if its attestation verifies.
    ///
    /// `Ok(None)` means this `Service` never issued the key. A registry that could not be read is
    /// an error and never `Ok(None)`: the two answer different questions, and collapsing them
    /// would turn an outage into a confident "no such key".
    ///
    /// The document is verified against the configured measurements, and the key it attests is
    /// checked against `public_key`, so an untrusted host cannot answer with another enclave's
    /// attestation.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if `public_key` is not 32 bytes of hex, the request fails, the
    /// host answers with any non-success status other than `404`, or the document does not
    /// verify.
    pub async fn signing_key(
        &self,
        public_key: &str,
        now: SystemTime,
    ) -> Result<Option<VerifiedSigningKey>, ClientError> {
        let digits = public_key.trim();
        let digits = digits.strip_prefix("0x").unwrap_or(digits);
        let requested = <[u8; SIGNING_PUBLIC_KEY_LEN]>::try_from(
            hex::decode(digits)
                .map_err(|_| ClientError::InvalidSigningKeyId)?
                .as_slice(),
        )
        .map_err(|_| ClientError::InvalidSigningKeyId)?;

        let url = format!(
            "{}{SIGNING_KEYS_PATH}/0x{}",
            self.config.host_url().as_str().trim_end_matches('/'),
            hex::encode(requested)
        );
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(ClientError::Request)?;

        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            let body = response.text().await.ok();
            return Err(Self::api_error(status.as_u16(), body.as_deref()));
        }

        let body: SigningKeyResponseBody = response
            .json()
            .await
            .map_err(ClientError::MalformedResponse)?;

        // The registry holds the document the enclave produced at boot, so this is verified as
        // of when it was signed rather than now. Liveness is the caller's policy, not this
        // lookup's: for anything but the currently running enclave it is unanswerable.
        let attestation = self
            .verifier
            .verify_stored_base64(body.attestation.trim(), now)?;
        if attestation.enclave_public_key != requested {
            return Err(ClientError::SigningKeyMismatch);
        }

        let signing_key = EdDSAPublicKey::from_compressed_bytes(requested)
            .map_err(|_| ClientError::InvalidSigningKey)?;

        Ok(Some(VerifiedSigningKey {
            attestation,
            signing_key,
            valid_from: body.valid_from,
            retired_at: body.retired_at,
            status: body.status,
        }))
    }

    /// Classifies a non-success response, reading the error envelope when there is one.
    fn api_error(status: u16, body: Option<&str>) -> ClientError {
        let Some(envelope) = body.and_then(|body| serde_json::from_str::<ApiErrorBody>(body).ok())
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

#[cfg(test)]
mod tests {
    use super::{KeyStatus, accepts_statement};

    const VALID_FROM: u64 = 100;

    #[test]
    fn an_active_key_accepts_anything_signed_after_it_was_attested() {
        assert!(accepts_statement(KeyStatus::Active, VALID_FROM, None, 100));
        assert!(accepts_statement(
            KeyStatus::Active,
            VALID_FROM,
            None,
            10_000
        ));
    }

    /// A key cannot have signed anything before the enclave attested it.
    #[test]
    fn nothing_predating_the_attestation_is_accepted() {
        assert!(!accepts_statement(KeyStatus::Active, VALID_FROM, None, 99));
    }

    /// Retirement is not revocation: what the enclave signed before shutting down still stands.
    #[test]
    fn a_retired_key_accepts_only_what_it_signed_before_retiring() {
        let retired_at = Some(200);

        assert!(accepts_statement(
            KeyStatus::Retired,
            VALID_FROM,
            retired_at,
            199
        ));
        assert!(!accepts_statement(
            KeyStatus::Retired,
            VALID_FROM,
            retired_at,
            200
        ));
        assert!(!accepts_statement(
            KeyStatus::Retired,
            VALID_FROM,
            retired_at,
            201
        ));
    }

    /// Placing the statement is impossible, and guessing would accept one signed after the
    /// enclave was gone.
    #[test]
    fn a_retired_key_with_no_retirement_time_accepts_nothing() {
        assert!(!accepts_statement(
            KeyStatus::Retired,
            VALID_FROM,
            None,
            150
        ));
    }

    /// Revocation is retroactive, so even a statement from before it is worthless.
    #[test]
    fn a_revoked_key_accepts_nothing() {
        assert!(!accepts_statement(
            KeyStatus::Revoked,
            VALID_FROM,
            None,
            150
        ));
        assert!(!accepts_statement(
            KeyStatus::Revoked,
            VALID_FROM,
            Some(200),
            150
        ));
    }
}

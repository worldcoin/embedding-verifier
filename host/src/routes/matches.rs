use axum::{Json, extract::State, http::StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use enclave_types::{self as enclave, MatchOutcome};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::challenge_fetch::FetchError;
use crate::error::AppError;

/// A match request.
///
/// `challenge_image_url` is plaintext so the host can fetch immediately; `ciphertext` is the
/// sealed request, which the host relays without being able to read it.
#[derive(Debug, Deserialize)]
pub struct MatchRequestBody {
    /// Where the RP put the encrypted challenge image.
    challenge_image_url: String,
    /// The sealed match request, base64.
    ciphertext: String,
}

/// A match response.
///
/// Both fields are opaque to this host: it can read neither the sealed outcome nor, usefully, the
/// attestation it relays alongside it.
#[derive(Debug, Serialize)]
pub struct MatchResponseBody {
    /// The sealed outcome, base64.
    response_ciphertext: String,
    /// The signing-key attestation, base64, so a client can verify the statement it just received.
    key_attestation: String,
}

/// Relays a sealed match request to the enclave.
///
/// The host's whole job here is routing and one fetch. It cannot read the request, cannot read the
/// response, and contributes only the HTTP status — derived from a coarse class the enclave
/// supplies. Rewriting that class would not let it forge an outcome, since the authoritative one
/// is sealed and a client compares the two.
///
/// # Errors
///
/// Returns [`AppError`] if the challenge image cannot be fetched or the enclave rejects the
/// request.
pub async fn handler(
    State(state): State<AppState>,
    Json(body): Json<MatchRequestBody>,
) -> Result<(StatusCode, Json<MatchResponseBody>), AppError> {
    let ciphertext = STANDARD.decode(body.ciphertext.trim()).map_err(|_| {
        AppError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The sealed match request was not valid base64",
            false,
        )
    })?;

    let challenge_ciphertext = state
        .challenge_source()
        .fetch(&body.challenge_image_url)
        .await
        .map_err(AppError::challenge_fetch)?;

    // Fetched before the enclave call and relayed unsealed: the attestation is public and
    // self-verifying, and a client needs it to check the statement it is about to receive. Taking
    // it from the host rather than the enclave keeps an NSM attestation off the per-match path;
    // caching it is tracked separately.
    let keys = state
        .enclave_client()
        .get_enclave_keys()
        .await
        .map_err(|error| AppError::enclave_match(&error))?;

    let response = state
        .enclave_client()
        .run_match(enclave::MatchRequest {
            body: ciphertext,
            challenge_ciphertext,
        })
        .await
        .map_err(|error| AppError::enclave_match(&error))?;

    let status = match response.outcome {
        MatchOutcome::Statement => StatusCode::OK,
        // Well-formed request, but the match did not hold. The reason is in the body, readable
        // only by the client.
        MatchOutcome::Rejected => StatusCode::UNPROCESSABLE_ENTITY,
    };

    Ok((
        status,
        Json(MatchResponseBody {
            response_ciphertext: STANDARD.encode(response.ciphertext),
            key_attestation: STANDARD.encode(keys.signing_key_attestation),
        }),
    ))
}

impl AppError {
    /// Maps a challenge-image fetch failure.
    ///
    /// The RP's bucket is an availability dependency of the match path, so its failures are
    /// attributed outward as `502` and never reported as an enclave fault. A rejected URL is the
    /// caller's problem instead, and is not retryable.
    #[must_use]
    pub fn challenge_fetch(error: FetchError) -> Self {
        match error {
            FetchError::Malformed | FetchError::NotAllowlisted => Self::new(
                StatusCode::BAD_REQUEST,
                "invalid_challenge_url",
                "The challenge image URL was rejected",
                false,
            ),
            FetchError::TooLarge => Self::new(
                StatusCode::BAD_GATEWAY,
                "challenge_fetch_failed",
                "The challenge image was too large",
                false,
            ),
            FetchError::Unreachable => Self::new(
                StatusCode::BAD_GATEWAY,
                "challenge_fetch_failed",
                "The challenge image could not be fetched",
                true,
            ),
        }
        .with_detail(format!("{error:?}"))
    }
}

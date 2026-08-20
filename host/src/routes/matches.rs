use axum::{Json, extract::State, http::StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use enclave_types::{self as enclave};
use serde::{Deserialize, Serialize};

use crate::AppState;
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
/// Both fields are opaque to this host.
#[derive(Debug, Serialize)]
pub struct MatchResponseBody {
    /// The sealed outcome, base64.
    response_ciphertext: String,
    /// The signing-key attestation, base64, so a client can verify the statement it just received.
    key_attestation: String,
}

/// Relays a sealed match request to the enclave.
///
/// The host's whole job is routing and one fetch. It contributes only the HTTP status, derived from
/// the coarse class the enclave supplies. Rewriting that class cannot forge an outcome: the
/// authoritative one is sealed, and a client compares the two.
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

    // Public and self-verifying, and the client needs it to check the statement. Taken from the
    // host rather than the enclave to keep an NSM call off the per-match path.
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

    // Always 200 when the enclave answered. Whether the match held is inside the ciphertext: it is
    // a fact about the request, so the status code must not carry it.
    Ok((
        StatusCode::OK,
        Json(MatchResponseBody {
            response_ciphertext: STANDARD.encode(response.ciphertext),
            key_attestation: STANDARD.encode(keys.signing_key_attestation),
        }),
    ))
}

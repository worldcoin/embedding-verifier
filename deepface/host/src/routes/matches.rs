use axum::{Json, extract::State, http::StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use deepface_types as enclave;
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
    ///
    /// TODO: Probably should be removed once we implement the key registry.
    key_attestation: String,
}

/// Relays a sealed match request to the enclave.
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

    let key_attestation = state
        .enclave_client()
        .signing_key_attestation()
        .await
        .map_err(|error| AppError::enclave_match(&error))?;

    tracing::info!(
        sealed_request_bytes = ciphertext.len(),
        challenge_ciphertext_bytes = challenge_ciphertext.len(),
        "forwarding sealed match request to enclave"
    );

    let response = state
        .enclave_client()
        .run_match(enclave::MatchRequest {
            body: ciphertext,
            challenge_ciphertext,
        })
        .await
        .map_err(|error| AppError::enclave_match(&error))?;

    // Always 200 when the enclave answered. Whether the match results (failure or success) must not be leaked to host.
    Ok((
        StatusCode::OK,
        Json(MatchResponseBody {
            response_ciphertext: STANDARD.encode(response.ciphertext),
            key_attestation: STANDARD.encode(key_attestation),
        }),
    ))
}

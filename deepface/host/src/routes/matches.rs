use axum::{Json, extract::State, http::StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use deepface_api_types::{MatchRequestBody, MatchResponseBody};
use deepface_enclave_types as enclave;

use crate::AppState;
use crate::error::AppError;

/// Relays a sealed match request to the enclave.
///
/// # Errors
///
/// Returns [`AppError`] if the id is rejected, the challenge image cannot be fetched, or the
/// enclave rejects the request.
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
        .fetch(&body.challenge_image_id)
        .await
        .map_err(AppError::challenge_fetch)?;

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
        }),
    ))
}

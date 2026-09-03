use axum::{Json, extract::State, extract::rejection::JsonRejection, http::StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use deepface_api_types::{MatchRequestBody, MatchResponseBody};
use deepface_enclave_types as enclave;

use crate::AppState;
use crate::error::AppError;

/// Largest match body this route accepts.
///
/// TODO: Increase this once PR for relaying image lands
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Relays a sealed match request to the enclave.
///
/// # Errors
///
/// Returns [`AppError`] if the body is rejected, the challenge image cannot be fetched, or the
/// enclave rejects the request.
pub async fn handler(
    State(state): State<AppState>,
    body: Result<Json<MatchRequestBody>, JsonRejection>,
) -> Result<(StatusCode, Json<MatchResponseBody>), AppError> {
    let Json(body) = body.map_err(|rejection| rejected_body(&rejection))?;

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

/// Maps a body the extractor refused.
///
/// Axum answers its own rejections with a bare status and a plaintext line, which is the one way
/// out of this service that carries no `code` for a client to branch on. Routing them through
/// [`AppError`] keeps that envelope universal. The size is only ever logged: it describes the
/// request, and a caller that sent it already knows.
fn rejected_body(rejection: &JsonRejection) -> AppError {
    let (status, code, message) = if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_too_large",
            "The match request was larger than this route accepts",
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The match request body was not the expected JSON",
        )
    };

    AppError::new(status, code, message, false)
        .with_detail(format!("{}; limit={MAX_BODY_BYTES}", rejection.body_text()))
}

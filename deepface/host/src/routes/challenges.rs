use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Json, response::IntoResponse};
use serde::Serialize;

use crate::AppState;
use crate::error::AppError;

/// The id under which the pushed challenge was stored.
#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    /// Handle the RP passes to the authenticator, which names it in `POST /v1/matches`.
    challenge_id: String,
}

/// Stores an RP's encrypted challenge image and returns its id.
///
/// The body is the raw AES-256-GCM ciphertext, not JSON: it is opaque bytes this host cannot
/// read, and base64 would inflate a multi-MB blob for nothing. The route's body limit enforces
/// [`crate::challenge_store::MAX_CHALLENGE_BYTES`].
///
/// # Errors
///
/// Returns [`AppError`]: `400` for an empty body, `503` if the store is full or unreachable.
pub async fn handler(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    if body.is_empty() {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "invalid_challenge",
            "The challenge ciphertext was empty",
            false,
        ));
    }

    let challenge_id = state
        .challenge_store()
        .put(body.to_vec())
        .await
        .map_err(|error| AppError::challenge_store(&error))?;

    tracing::info!(
        challenge_bytes = body.len(),
        %challenge_id,
        "stored a pushed challenge"
    );

    Ok((
        StatusCode::CREATED,
        Json(ChallengeResponse {
            challenge_id: challenge_id.to_string(),
        }),
    ))
}

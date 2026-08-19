use axum::{Json, body::Bytes, extract::State, http::StatusCode};
use enclave_types::{self as enclave};
use serde::Serialize;

use crate::error::AppError;
use crate::types::AppState;

/// A match statement rendered for HTTP clients.
///
/// Binary fields keep their fixed-size type and serialize as hex strings.
#[derive(Debug, Serialize)]
pub struct MatchStatement {
    version: u8,
    #[serde(with = "hex::serde")]
    live_image_hash: [u8; 32],
    #[serde(with = "hex::serde")]
    credential_claim: [u8; 32],
    #[serde(with = "hex::serde")]
    challenger_image_hash: [u8; 32],
    match_coefficient: f32,
}

/// A successful match response.
#[derive(Debug, Serialize)]
pub struct MatchResponse {
    statement: MatchStatement,
    /// Serialized as hex. Length is not yet pinned — signing is still a placeholder.
    #[serde(with = "hex::serde")]
    signature: Vec<u8>,
}

impl From<enclave::MatchResponse> for MatchResponse {
    fn from(response: enclave::MatchResponse) -> Self {
        let enclave::MatchStatement {
            version,
            live_image_hash,
            credential_claim,
            challenger_image_hash,
            match_coefficient,
        } = response.statement;

        Self {
            statement: MatchStatement {
                version,
                live_image_hash,
                credential_claim,
                challenger_image_hash,
                match_coefficient,
            },
            signature: response.signature,
        }
    }
}

/// Forwards a sealed match request to the enclave.
///
/// The request body is the raw sealed-box ciphertext (`application/octet-stream`); the host
/// relays it opaquely and never inspects it.
///
/// # Errors
///
/// Returns [`AppError`] if the body is empty or the enclave rejects the request.
pub async fn handler(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<MatchResponse>, AppError> {
    if body.is_empty() {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The match request body was empty",
            false,
        ));
    }

    let response = state
        .enclave_client()
        .run_match(enclave::MatchRequest {
            sealed_payload: body.to_vec(),
        })
        .await
        .map_err(|error| AppError::enclave_match(&error))?;

    Ok(Json(response.into()))
}

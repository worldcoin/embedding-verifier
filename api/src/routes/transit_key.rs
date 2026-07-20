use axum::{Json, extract::State, http::StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;

use crate::types::AppState;

#[derive(Debug, Serialize)]
pub struct TransitKeyResponse {
    attestation: String,
}

pub async fn handler(
    State(state): State<AppState>,
) -> Result<Json<TransitKeyResponse>, StatusCode> {
    let response = state
        .enclave_client()
        .get_transit_key()
        .await
        .map_err(|error| {
            tracing::error!(?error, "failed to fetch enclave transit key");
            StatusCode::SERVICE_UNAVAILABLE
        })?;

    Ok(Json(TransitKeyResponse {
        attestation: STANDARD.encode(response.attestation),
    }))
}

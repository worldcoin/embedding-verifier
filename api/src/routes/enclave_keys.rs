use axum::{Json, extract::State, http::StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;

use crate::types::AppState;

/// One attestation document per boot-scoped enclave public key.
///
/// Both are public and relayed unsealed; the host cannot read or verify either.
#[derive(Debug, Serialize)]
pub struct EnclaveKeysResponse {
    encryption_key_attestation: String,
    signing_key_attestation: String,
}

pub async fn handler(
    State(state): State<AppState>,
) -> Result<Json<EnclaveKeysResponse>, StatusCode> {
    // TODO: Cache the attestation documents, invalidating on enclave reconnect, and bound
    // the entry's lifetime by the document certificate's validity.
    let response = state
        .enclave_client()
        .get_enclave_keys()
        .await
        .map_err(|error| {
            tracing::error!(?error, "failed to fetch enclave key attestations");
            StatusCode::SERVICE_UNAVAILABLE
        })?;

    Ok(Json(EnclaveKeysResponse {
        encryption_key_attestation: STANDARD.encode(response.encryption_key_attestation),
        signing_key_attestation: STANDARD.encode(response.signing_key_attestation),
    }))
}

use axum::{Json, extract::State};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;

use crate::error::AppError;
use crate::types::AppState;

/// The enclave assigned to a client, as an attestation document.
///
/// The document already carries the enclave's identity and expiry, and the client verifies it
/// before trusting either, so the host relays opaque bytes and adds no fields of its own.
#[derive(Debug, Serialize)]
pub struct EnclaveAssignmentResponse {
    attestation: String,
}

/// Assigns this host's enclave by returning its encryption-key attestation.
///
/// # Errors
///
/// Returns [`AppError`] if the enclave is unreachable or cannot attest.
pub async fn handler(
    State(state): State<AppState>,
) -> Result<Json<EnclaveAssignmentResponse>, AppError> {
    // TODO: Cache the attestation document, invalidating on enclave reconnect, and bound the
    // entry's lifetime by the document certificate's validity. Until then every request costs
    // an NSM attestation, so this route must not carry production traffic uncapped.
    let response = state
        .enclave_client()
        .get_enclave_keys()
        .await
        .map_err(|error| AppError::enclave_assignment(&error))?;

    Ok(Json(EnclaveAssignmentResponse {
        attestation: STANDARD.encode(response.encryption_key_attestation),
    }))
}

use axum::{Json, extract::State};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;

use crate::AppState;
use crate::error::AppError;

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
    // The enclave caches this document and refreshes it ahead of use, so the call costs a vsock
    // round trip rather than an NSM attestation. Caching it here instead would need a boot
    // identifier and invalidation; caching it there cannot outlive the keys it describes.
    let response = state
        .enclave_client()
        .get_enclave_keys()
        .await
        .map_err(|error| AppError::enclave_assignment(&error))?;

    Ok(Json(EnclaveAssignmentResponse {
        attestation: STANDARD.encode(response.encryption_key_attestation),
    }))
}

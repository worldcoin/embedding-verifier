use axum::{Json, extract::State, http::StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;

use crate::types::AppState;

#[derive(Debug, Serialize)]
pub struct TransitKeyResponse {
    attestation: String,
}

/// Serves the NSM attestation document binding the enclave's transit public key.
///
/// No client nonce is bound into it, and that is settled rather than pending: the claim
/// the document makes is "this key lives in an enclave running image X", which is
/// time-invariant, so a replayed document states something true. The age bound the design
/// actually needs comes from the Nitro leaf certificate, which lives three hours and
/// whose validity the client already has to check. What the client must *also* check, and
/// what AWS's own write-ups stop short of, is the pinned `PCR0/1/2` (`PCR8` if the EIF is
/// signed) plus an explicit rejection of zeroed PCRs — zeroed PCRs mean `--debug-mode`,
/// which is what our development deployment runs.
pub async fn handler(
    State(state): State<AppState>,
) -> Result<Json<TransitKeyResponse>, StatusCode> {
    // TODO: Cache the attestation, invalidating it when the enclave's liveness signal breaks.
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

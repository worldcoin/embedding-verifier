use axum::{extract::State, http::StatusCode};

use crate::AppState;

/// Readiness, not liveness: this host takes traffic only once its enclave answers *and* the key
/// that will sign its statements is one an RP can look up.
pub async fn handler(State(state): State<AppState>) -> StatusCode {
    if state.registered_signing_key().is_none() {
        tracing::warn!(
            dependency = "key-registry",
            "readiness: this boot's signing key is not registered yet"
        );
        return StatusCode::SERVICE_UNAVAILABLE;
    }

    match state.enclave_client().health().await {
        Ok(()) => StatusCode::OK,
        Err(error) => {
            tracing::warn!(?error, "enclave readiness check failed");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

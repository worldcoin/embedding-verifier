use axum::{extract::State, http::StatusCode};

use crate::types::AppState;

/// Reports whether the API can serve traffic, which requires a reachable enclave.
///
/// This is also the host's liveness feed for the enclave: it calls the enclave on every
/// poll, so a restart shows up here first and invalidates anything cached against the
/// previous boot.
pub async fn handler(State(state): State<AppState>) -> StatusCode {
    match state.enclave_client().health().await {
        Ok(()) => StatusCode::OK,
        Err(error) => {
            tracing::warn!(?error, "enclave readiness check failed");
            state.observe_enclave_failure(&error);
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

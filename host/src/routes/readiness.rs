use axum::{extract::State, http::StatusCode};

use crate::types::AppState;

pub async fn handler(State(state): State<AppState>) -> StatusCode {
    match state.enclave_client().health().await {
        Ok(()) => StatusCode::OK,
        Err(error) => {
            tracing::warn!(?error, "enclave readiness check failed");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

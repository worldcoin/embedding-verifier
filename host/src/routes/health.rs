use axum::{extract::State, http::StatusCode};

use crate::types::AppState;

/// Handles API health checks.
pub async fn handler(State(_state): State<AppState>) -> StatusCode {
    StatusCode::OK
}

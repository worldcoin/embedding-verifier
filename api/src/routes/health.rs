use axum::{extract::State, http::StatusCode};

use crate::types::Environment;

/// Handles API health checks.
pub async fn handler(State(_environment): State<Environment>) -> StatusCode {
    StatusCode::OK
}

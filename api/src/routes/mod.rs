//! HTTP route definitions.

mod enclave_assignment;
mod health;
mod matches;
mod readiness;

use axum::{
    Router,
    routing::{get, post},
};

use crate::types::AppState;

/// Builds the router with all API routes.
pub fn handler() -> Router<AppState> {
    Router::new()
        .route("/health", get(health::handler))
        .route("/ready", get(readiness::handler))
        .route("/v1/enclave-assignment", post(enclave_assignment::handler))
        .route("/v1/matches", post(matches::handler))
}

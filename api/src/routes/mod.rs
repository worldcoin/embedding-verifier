//! HTTP route definitions.

mod health;
mod readiness;
mod transit_key;

use axum::{Router, routing::get};

use crate::types::AppState;

/// Builds the router with all API routes.
pub fn handler() -> Router<AppState> {
    Router::new()
        .route("/health", get(health::handler))
        .route("/ready", get(readiness::handler))
        .route("/v1/enclave/transit-key", get(transit_key::handler))
}

//! HTTP route definitions.

mod face_comparison;
mod health;
mod matches;
mod readiness;
mod transit_key;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};

use crate::types::AppState;

const FACE_COMPARISON_BODY_LIMIT: usize = 24 * 1024 * 1024;

/// Builds the router with all API routes.
pub fn handler() -> Router<AppState> {
    Router::new()
        .route("/health", get(health::handler))
        .route("/ready", get(readiness::handler))
        .route("/v1/enclave/transit-key", get(transit_key::handler))
        .route("/v1/matches", post(matches::handler))
        .route(
            "/v1/compare-faces",
            post(face_comparison::handler).layer(DefaultBodyLimit::max(FACE_COMPARISON_BODY_LIMIT)),
        )
}

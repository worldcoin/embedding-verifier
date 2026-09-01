//! HTTP route definitions.

mod challenges;
mod enclave_assignment;
mod health;
mod matches;
mod readiness;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};

use crate::AppState;
use crate::challenge_store::MAX_CHALLENGE_BYTES;

/// Builds the router with all API routes.
pub fn handler() -> Router<AppState> {
    Router::new()
        .route("/health", get(health::handler))
        .route("/ready", get(readiness::handler))
        .route("/v1/enclave-assignment", post(enclave_assignment::handler))
        .route(
            "/v1/challenges",
            // Enforced while the body streams in, so an oversized push is refused (413) rather
            // than buffered. Axum answers without an error envelope; the cap is the contract.
            post(challenges::handler).layer(DefaultBodyLimit::max(MAX_CHALLENGE_BYTES)),
        )
        .route("/v1/matches", post(matches::handler))
}

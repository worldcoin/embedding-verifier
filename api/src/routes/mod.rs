//! HTTP route definitions.

mod health;

use axum::{Router, routing::get};

use crate::types::Environment;

/// Builds the router with all API routes.
pub fn handler() -> Router<Environment> {
    Router::new().route("/health", get(health::handler))
}

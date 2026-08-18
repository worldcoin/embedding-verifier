//! HTTP route definitions.

mod health;
mod matches;
mod readiness;
mod transit_key;

use axum::{
    Router, middleware,
    routing::{get, post},
};

use crate::telemetry::http::record_metrics;
use crate::types::AppState;

/// Builds the router with all API routes.
///
/// `/health` and `/ready` are transitional aliases for the spec's `/healthz` and `/readyz`.
/// The running deployment probes the old paths, so serving both keeps a rolling deploy from
/// stalling on pods that never report ready. They come out once the deploy values move.
pub fn handler(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health::handler))
        .route("/health", get(health::handler))
        .route("/readyz", get(readiness::handler))
        .route("/ready", get(readiness::handler))
        .route("/v1/enclave/transit-key", get(transit_key::handler))
        .route("/v1/matches", post(matches::handler))
        // `route_layer` rather than `layer`: it runs inside the routing decision, so the
        // matched route pattern is available to tag metrics with.
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            record_metrics,
        ))
        .with_state(state)
}

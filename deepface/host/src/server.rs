//! Axum server setup and lifecycle.

use std::{net::SocketAddr, time::Instant};

use anyhow::Context;
use axum::{
    extract::{MatchedPath, Request},
    middleware::{self, Next},
    response::Response,
};
use telemetry_batteries::{
    reexports::metrics::{counter, gauge, histogram},
    tracing::middleware::TraceLayer,
};
use tokio::net::TcpListener;

use crate::{AppState, routes};

const DEFAULT_PORT: u16 = 8000;

/// Starts the API server.
///
/// # Errors
///
/// Returns an error when the configured port is invalid, the listener cannot bind, or the server
/// exits unexpectedly.
pub async fn start(state: AppState) -> anyhow::Result<()> {
    let port = std::env::var("PORT").map_or(Ok(DEFAULT_PORT), |value| value.parse())?;
    let address = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("failed to bind API to {address}"))?;

    tracing::info!(%address, "API listening");

    axum::serve(
        listener,
        routes::handler()
            .with_state(state)
            .layer(middleware::from_fn(observe_http_request))
            .layer(TraceLayer::new())
            .into_make_service(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("API server failed")
}

/// Adds low-cardinality route information to the HTTP span and records the basic RED metrics.
async fn observe_http_request(request: Request, next: Next) -> Response {
    let method = request.method().to_string();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("unknown", MatchedPath::as_str)
        .to_owned();

    let span = tracing::Span::current();
    span.record("http.route", route.as_str());
    span.record("otel.name", format_args!("{method} {route}"));

    let active_requests = gauge!(
        "http.server.active_requests",
        "http.request.method" => method.clone(),
        "http.route" => route.clone(),
    );
    active_requests.increment(1.0);
    let _active_request = ActiveRequestGuard(active_requests);

    let started_at = Instant::now();
    let response = next.run(request).await;
    let status = response.status().as_u16().to_string();

    counter!(
        "http.server.request.count",
        "http.request.method" => method.clone(),
        "http.route" => route.clone(),
        "http.response.status_code" => status.clone(),
    )
    .increment(1);
    histogram!(
        "http.server.request.duration",
        "http.request.method" => method,
        "http.route" => route,
        "http.response.status_code" => status,
    )
    .record(started_at.elapsed().as_secs_f64());

    response
}

struct ActiveRequestGuard(telemetry_batteries::reexports::metrics::Gauge);

impl Drop for ActiveRequestGuard {
    fn drop(&mut self) {
        self.0.decrement(1.0);
    }
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "failed to install shutdown signal handler");
    }
}

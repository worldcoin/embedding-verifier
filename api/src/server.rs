//! Axum server setup and lifecycle.

use std::{net::SocketAddr, time::Duration};

use anyhow::Context;
use tokio::{net::TcpListener, signal::unix::SignalKind};
use tower_http::trace::TraceLayer;

use crate::readiness::Readiness;
use crate::telemetry::http;
use crate::types::AppState;

/// Starts the API server and serves until a shutdown signal arrives.
///
/// # Errors
///
/// Returns an error when the listener cannot bind or the server exits unexpectedly.
pub async fn start(state: AppState) -> anyhow::Result<()> {
    let address = SocketAddr::from(([0, 0, 0, 0], state.config().port));
    let drain = state.config().shutdown_drain;
    let readiness = state.readiness();

    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("failed to bind API to {address}"))?;

    tracing::info!(%address, "API listening");

    // Each `.layer` wraps the previous, so this reads innermost-first: the id is minted
    // outermost, the span below it sees it, and it is echoed onto the response on the way
    // back out.
    let app = crate::routes::handler(state)
        .layer(http::propagate_request_id_layer())
        .layer(TraceLayer::new_for_http().make_span_with(http::make_span))
        .layer(http::set_request_id_layer());

    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(drain_then_shutdown(readiness, drain))
        .await
        .context("API server failed")
}

/// Resolves once the process should stop accepting new connections.
///
/// Goes unready *before* the drain window rather than after, so the load balancer stops
/// routing here while we are still able to finish what is already in flight. Returning
/// immediately on signal would drop in-flight requests that the balancer has not yet
/// learned to stop sending.
async fn drain_then_shutdown(readiness: std::sync::Arc<Readiness>, drain: Duration) {
    await_signal().await;

    readiness.begin_draining();
    tracing::warn!(
        drain_seconds = drain.as_secs(),
        "shutdown signal received — draining"
    );

    tokio::time::sleep(drain).await;

    tracing::warn!("drain complete — shutting down");
}

/// Waits for SIGTERM or SIGINT.
///
/// SIGTERM is what Kubernetes sends; handling only ctrl-c would mean every pod termination
/// is an ungraceful kill after the grace period expires.
async fn await_signal() {
    let mut terminate = match tokio::signal::unix::signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(error) => {
            tracing::error!(%error, "failed to install SIGTERM handler");
            return;
        }
    };

    tokio::select! {
        _ = terminate.recv() => tracing::warn!("received SIGTERM"),
        result = tokio::signal::ctrl_c() => match result {
            Ok(()) => tracing::warn!("received SIGINT"),
            Err(error) => tracing::error!(%error, "failed to install SIGINT handler"),
        },
    }
}

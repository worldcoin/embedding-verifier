//! Axum server setup and lifecycle.

use std::net::SocketAddr;

use anyhow::Context;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;

use crate::{routes, types::Environment};

const DEFAULT_PORT: u16 = 8000;

/// Starts the API server.
///
/// # Errors
///
/// Returns an error when the configured port is invalid, the listener cannot bind, or the server
/// exits unexpectedly.
pub async fn start(environment: Environment) -> anyhow::Result<()> {
    let port = std::env::var("PORT").map_or(Ok(DEFAULT_PORT), |value| value.parse())?;
    let address = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("failed to bind API to {address}"))?;

    tracing::info!(%address, "API listening");

    axum::serve(
        listener,
        routes::handler()
            .with_state(environment)
            .layer(TraceLayer::new_for_http())
            .into_make_service(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("API server failed")
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "failed to install shutdown signal handler");
    }
}

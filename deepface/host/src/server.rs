//! Axum server setup and lifecycle.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use telemetry_batteries::tracing::middleware::TraceLayer;
use tokio::net::TcpListener;
use tokio::time::timeout;

use crate::key_registry::{retire_signing_key, unix_seconds};
use crate::{AppState, routes};

const DEFAULT_PORT: u16 = 8000;

/// Budget for marking this boot's key retired once the server has drained.
///
/// Short on purpose: the pod's termination grace period is the real limit, and a key left
/// `active` costs nothing — it only ever existed in the enclave's memory, which is gone.
const RETIRE_TIMEOUT: Duration = Duration::from_secs(5);

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

    let result = axum::serve(
        listener,
        routes::handler()
            .with_state(state.clone())
            .layer(TraceLayer::new())
            .into_make_service(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("API server failed");

    retire(&state).await;

    result
}

/// Records that this enclave shut down normally, so a verifier can tell that from a revocation.
///
/// Best effort. A failure here leaves the row `active`, which is wrong but not unsafe; failing
/// the shutdown over it would be worse.
async fn retire(state: &AppState) {
    let Some(public_key) = state.registered_signing_key() else {
        return;
    };

    let registry = state.key_registry();

    match timeout(
        RETIRE_TIMEOUT,
        retire_signing_key(registry.as_ref(), public_key, unix_seconds()),
    )
    .await
    {
        Ok(Ok(())) => tracing::info!(%public_key, "retired this boot's signing key"),
        Ok(Err(error)) => tracing::error!(
            %public_key,
            %error,
            dependency = "key-registry",
            "failed to retire this boot's signing key; it stays active in the registry"
        ),
        Err(_) => tracing::error!(
            %public_key,
            timeout = ?RETIRE_TIMEOUT,
            dependency = "key-registry",
            "timed out retiring this boot's signing key; it stays active in the registry"
        ),
    }
}

/// Resolves on the first shutdown signal. SIGTERM as well as Ctrl-C, since that is what an
/// orchestrator sends when it drains a pod.
async fn shutdown_signal() {
    let interrupt = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to install Ctrl-C handler");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => tracing::info!("received Ctrl-C, draining"),
        () = terminate => tracing::info!("received SIGTERM, draining"),
    }
}

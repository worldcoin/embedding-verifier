//! Migration API and enclave relay for the `DeepIdentifier` migration — the untrusted side.
//!
//! Skeleton. The routes it replaces are §6 of the spec.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

use std::process::ExitCode;

use tracing_subscriber::EnvFilter;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Non-zero rather than binding a port: a skeleton that answers /healthz reads as green.
    tracing::error!("di-host is a skeleton and serves no routes yet");
    ExitCode::FAILURE
}

//! Nitro enclave workload for the `DeepIdentifier` migration — the trusted side.
//!
//! Skeleton. The boot sequence it replaces is §7.1 of the spec.

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

    // Non-zero rather than idling: a skeleton that stays up reads as healthy.
    tracing::error!("di-enclave is a skeleton and has no boot sequence yet");
    ExitCode::FAILURE
}

//! Migration API and enclave relay for the `DeepIdentifier` migration — the untrusted side.
//!
//! Skeleton. What this replaces is §6 of the spec: enclave assignment, job enqueue and result
//! polling on the outside; pulling its own queue, fetching the staged object and relaying
//! ciphertext and KMS blobs it cannot open on the inside. None of that exists yet.

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

    // Exits non-zero rather than binding a port: a host that serves nothing but answers
    // `/healthz` would read as green to a load balancer.
    tracing::error!("di-host is a skeleton and serves no routes yet");
    ExitCode::FAILURE
}

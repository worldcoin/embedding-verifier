//! Nitro enclave workload for the `DeepIdentifier` migration — the trusted side.
//!
//! Skeleton. The boot sequence this replaces is §7.1 of the spec: verify the NSM is the entropy
//! source, generate the per-boot X25519 encryption key and the RSA key KMS unwraps against,
//! take the `Signing Key` release, load and hash-check the model bundle, run the self-test
//! vector, and only then serve. None of that exists yet.

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

    // Exits non-zero rather than idling: an enclave that boots and sits there looks alive to
    // anything watching the process, and a skeleton must never be mistaken for a working one.
    tracing::error!("di-enclave is a skeleton and has no boot sequence yet");
    ExitCode::FAILURE
}

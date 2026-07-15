//! Secure-enclave runtime for private face verification.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

/// Pontifex operations exposed to the API host.
pub mod pontifex_server;

//! Secure-enclave runtime for private face verification.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

/// PCP binding verification (transport-free).
pub mod pcp;
/// Pontifex operations exposed to the API host.
pub mod pontifex_server;
/// Nitro hardware RNG verification.
pub mod rng;
/// Boot-scoped enclave state.
pub mod state;

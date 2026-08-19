//! HTTP host for the embedding verifier — the untrusted side of the enclave boundary.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

pub mod enclave;
pub mod error;
pub mod routes;
pub mod server;
pub mod types;

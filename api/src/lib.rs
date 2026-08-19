//! HTTP API for the embedding verifier.

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

//! HTTP host for the embedding verifier — the untrusted side of the enclave boundary.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod app_state;
mod environment;

pub mod challenge_fetch;
pub mod enclave;
pub mod error;
pub mod routes;
pub mod server;

pub use app_state::AppState;
pub use environment::Environment;

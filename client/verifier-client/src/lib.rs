//! Client for the embedding verifier's enclave-assignment flow.
//!
//! Fetches an assignment, verifies the AWS Nitro attestation document it carries, and yields
//! the enclave's encryption public key. The host is untrusted, so the enclave's identity,
//! measurements and public key are all read from the signed document.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

pub mod client;
pub mod config;
pub mod nitro;

pub use client::{ClientError, FaceVerifierClient};
pub use config::{Config, ConfigError};

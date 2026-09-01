//! Client for the embedding verifier's enclave-assignment flow.
//!
//! Fetches an assignment, verifies the AWS Nitro attestation document it carries, and yields
//! a [`Requester`] for sealing requests to the enclave. The host is untrusted, so
//! the enclave's identity, measurements and public key are all read from the signed document.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod client;
mod config;

pub use attested_channel::channel::Requester;
pub use attested_channel::nitro;
pub use client::{
    ClientError, FaceVerifierClient, KeyStatus, VerifiedAssignment, VerifiedSigningKey,
};
pub use config::{Config, ConfigError};

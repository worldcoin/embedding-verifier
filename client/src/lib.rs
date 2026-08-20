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

/// The attestation verifier, re-exported from `crypto`.
///
/// Callers need [`nitro::PcrMeasurement`] to build a [`Config`], so it is reachable here
/// rather than only through a second dependency.
pub use crypto::nitro;

pub use client::{ClientError, FaceVerifierClient, VerifiedAssignment};
pub use config::{Config, ConfigError};
pub use crypto::sealed_channel::Requester;

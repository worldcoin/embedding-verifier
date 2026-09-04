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
pub mod config;

pub use attested_channel::channel::Requester;
pub use attested_channel::nitro;
pub use client::{Error, FaceVerifierClient, VerifiedAssignment};
pub use config::Config;

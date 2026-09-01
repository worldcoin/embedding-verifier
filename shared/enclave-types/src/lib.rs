//! The vsock wire contract every host↔enclave pair shares: health, errors, key attestation.
//!
//! Anything specific to one workload belongs in that workload's own types crate, which keeps
//! its request shapes out of the other's enclave image.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod enclave_keys;
mod error;
mod health;

pub use enclave_keys::{GetEncryptionKeyRequest, GetSigningKeyRequest, KeyAttestation};
pub use error::EnclaveError;
pub use health::HealthRequest;

//! The vsock contract between the `Verifier` host and its enclave.
//!
//! The client↔host HTTP contract is `flamingo-verifier-api-types`; the sealed client↔enclave payload is
//! `flamingo-verifier-protocol`.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod error;
mod health;
mod keys;
mod matches;

pub use error::EnclaveError;
pub use health::HealthRequest;
pub use keys::{GetEncryptionKeyRequest, KeyAttestation};
pub use matches::{MatchRequest, MatchResponse};

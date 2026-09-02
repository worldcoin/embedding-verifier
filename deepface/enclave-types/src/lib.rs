//! The vsock wire contract between the `DeepFace` host and its enclave: health, errors, key
//! attestation, and the match exchange.
//!
//! One of three contracts this workload speaks, each in its own crate so no boundary's types
//! reach a peer that has no business with them. `deepface-api-types` is the HTTP contract the
//! client speaks to the host; `deepface-protocol` is the sealed payload that travels
//! end-to-end between the client and the enclave, which this host only relays.

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
pub use keys::{GetEncryptionKeyRequest, GetSigningKeyRequest, KeyAttestation};
pub use matches::{MatchRequest, MatchResponse};

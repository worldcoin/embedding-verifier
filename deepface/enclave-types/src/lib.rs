//! The vsock contract between the `DeepFace` host and its enclave.
//!
//! The client↔host HTTP contract is `deepface-api-types`; the sealed client↔enclave payload is
//! `deepface-protocol`.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod error;
mod extract_embedding;
mod health;
mod keys;
mod matches;

pub use error::EnclaveError;
pub use extract_embedding::{ExtractEmbeddingRequest, ExtractEmbeddingResponse};
pub use health::HealthRequest;
pub use keys::{GetEncryptionKeyRequest, KeyAttestation};
pub use matches::{MatchRequest, MatchResponse};

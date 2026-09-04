//! Everything the `Verifier` enclave speaks: the vsock contract it serves the host, and the
//! sealed contract it serves the client.
//!
//! The client↔host HTTP contract is `flamingo-verifier-api-types`; the signed statement a
//! successful [`MatchResult`] carries is `flamingo-verifier-protocol`.

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
mod messages;

pub use error::{EnclaveError, FramingError};
pub use health::HealthRequest;
pub use keys::{GetEncryptionKeyRequest, KeyAttestation};
pub use matches::{MatchRequest, MatchResponse};
pub use messages::{
    AttestedStatement, FailureReason, MATCH_RESULT_ENVELOPE_LEN, MatchInputs, MatchResult,
};

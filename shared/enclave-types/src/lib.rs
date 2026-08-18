//! Wire types shared by the API host and secure enclave.

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
mod matches;
/// The HPKE contract for payloads sealed to the enclave.
#[cfg(feature = "sealing")]
pub mod sealing;

pub use enclave_keys::{GetEnclaveKeysRequest, GetEnclaveKeysResponse};
pub use error::EnclaveError;
pub use health::HealthRequest;
pub use matches::{MatchOutcome, MatchRequest, MatchResponse, MatchStatement};

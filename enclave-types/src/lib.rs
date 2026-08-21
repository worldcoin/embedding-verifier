//! Wire types shared by the host and enclave.

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

pub use enclave_keys::{GetEnclaveKeysRequest, GetEnclaveKeysResponse};
pub use error::EnclaveError;
pub use health::HealthRequest;
pub use matches::{MatchRequest, MatchResponse};

//! Wire types shared by the API host and secure enclave.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod error;
mod health;
mod transit_key;

pub use error::EnclaveError;
pub use health::HealthRequest;
pub use transit_key::{GetTransitKeyRequest, GetTransitKeyResponse};

//! Wire types shared by the API host and secure enclave.

mod error;
mod health;

pub use error::EnclaveError;
pub use health::HealthRequest;

//! Wire types shared by the API host and secure enclave.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod error;
mod face_comparison;
mod health;
mod matches;
mod transit_key;

pub use error::EnclaveError;
pub use face_comparison::{CompareFacesRequest, CompareFacesResponse};
pub use health::HealthRequest;
pub use matches::{MatchRequest, MatchResponse, MatchStatement};
pub use transit_key::{GetTransitKeyRequest, GetTransitKeyResponse};

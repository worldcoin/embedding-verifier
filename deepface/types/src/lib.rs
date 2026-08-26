//! The vsock wire contract for the `DeepFace` match. What every workload shares comes from
//! [`enclave_types`].

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod matches;

pub use matches::{MatchRequest, MatchResponse};

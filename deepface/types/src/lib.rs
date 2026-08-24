//! The vsock wire contract for the `DeepFace` match, carried between the host and the enclave.
//!
//! The exchanges every workload shares — health, errors, key attestation — come from
//! [`enclave_types`]; only the match itself lives here.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod matches;

pub use matches::{MatchRequest, MatchResponse};

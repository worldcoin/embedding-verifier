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
mod matches;
mod transit_key;

pub use error::EnclaveError;
pub use health::HealthRequest;
pub use matches::{
    AEAD_TAG_LEN, CHANNEL_VERSION, ENCAPPED_KEY_LEN, MatchOutcome, MatchOutcomePayload,
    MatchRequest, MatchResponse, MatchStatement, RESPONSE_KEY_LABEL, RESPONSE_KEY_LEN,
    RESPONSE_NONCE_LABEL, RESPONSE_NONCE_LEN, RejectReason, channel_info,
};
pub use transit_key::{GetTransitKeyRequest, GetTransitKeyResponse};

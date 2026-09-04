//! The sealed client↔enclave match payload. The host relays the ciphertext and does not link this.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod error;
mod messages;

/// Version of the Flamingo match payload.
pub const MATCH_PROTOCOL_VERSION: u8 = 1;

/// Pontifex channel domain shared by the consumer and enclave.
pub const MATCH_CHANNEL_DOMAIN: &str = "flamingo-verifier/matches";

pub use error::Error;
pub use messages::{
    AttestedStatement, FailureReason, MATCH_RESULT_ENVELOPE_LEN, MatchInputs, MatchResult,
};

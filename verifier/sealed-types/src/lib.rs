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

/// Pontifex channel domain shared by the consumer and enclave.
pub const MATCH_CHANNEL_DOMAIN: &str = "flamingo-verifier/matches/v1";

pub use error::Error;
pub use messages::{
    AttestedStatement, FailureReason, MATCH_RESULT_ENVELOPE_LEN, MatchInputs, MatchResult,
};

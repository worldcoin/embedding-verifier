//! The sealed `DeepFace` face-processing protocol.
//!
//! [`messages`] holds both ends of one exchange; [`match_token`] holds the signed statement a
//! successful [`messages::MatchResult`] carries.
//!
//! Both halves travel end-to-end between the client and the enclave, sealed by
//! [`attested_channel::channel`]. The host relays the ciphertext and links none of this.
//!
//! Work in progress — no external security review yet, and the token format is provisional
//! pending protocol sign-off. Not production ready.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

pub mod embedding;
pub mod error;
pub mod match_token;
pub mod messages;

pub use error::Error;

//! Cryptography shared by clients, enclaves and RPs.
//!
//! Work in progress — no external security review yet, formats and wire contract may still
//! change, and parts are provisional pending protocol sign-off. Not production ready.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

pub mod match_token;
pub mod payload;
pub mod sealed_channel;
pub mod sealed_channel;

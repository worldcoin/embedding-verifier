//! Establishing a confidential channel to a specific, measured AWS Nitro enclave.
//!
//! Deliberately not the host↔enclave vsock hop, which is `enclave-types` plus pontifex. This
//! is the end-to-end client↔enclave path, and the host is one of the parties it excludes.
//!
//! Expected to move into [pontifex](https://github.com/worldcoin/pontifex) once it settles —
//! nothing here is specific to this workspace's use case.
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

pub mod channel;

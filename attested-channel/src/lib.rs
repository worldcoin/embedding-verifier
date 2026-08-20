//! Establishing a confidential channel to a specific, measured AWS Nitro enclave.
//! Expected to move into [pontifex](https://github.com/worldcoin/pontifex)

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

pub mod channel;
#[cfg(feature = "attestation")]
pub mod nitro;

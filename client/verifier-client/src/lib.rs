//! Client for the embedding verifier's enclave-assignment flow.
//!
//! Fetches an enclave assignment from the host, verifies the AWS Nitro attestation document
//! it carries, and yields the enclave's encryption public key. The host is untrusted and
//! relays the document opaquely, so everything the caller relies on — the enclave's identity,
//! its measurements, its public key — is read out of the signed document here.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

pub mod http;
pub mod nitro;
pub mod policy;

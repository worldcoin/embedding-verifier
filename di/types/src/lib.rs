//! The vsock wire contract for the `DeepIdentifier` migration, carried between the host and the
//! enclave.
//!
//! Skeleton: no request types yet. The exchanges every workload shares — health, errors, key
//! attestation — already come from [`enclave_types`]; what belongs here is the migration job
//! itself (the staged ciphertext, its digest, and the self-custody key sealed to this enclave),
//! which the spec's `POST /v1/migrations` still has as work in progress.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

// Re-exported so downstream crates take the shared contract from one place, and so this crate
// has a compiled dependency on it before the migration types land.
pub use enclave_types::{
    EnclaveError, GetEncryptionKeyRequest, GetSigningKeyRequest, HealthRequest, KeyAttestation,
};

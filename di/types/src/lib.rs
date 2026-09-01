//! The vsock wire contract for the `DeepIdentifier` migration.
//!
//! Skeleton: the migration job itself is still work in progress in the spec. What every
//! workload shares comes from [`enclave_types`] and is re-exported here.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

pub use enclave_types::{
    EnclaveError, GetEncryptionKeyRequest, GetSigningKeyRequest, HealthRequest, KeyAttestation,
};

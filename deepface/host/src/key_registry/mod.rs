//! The `Signing Key` registry.
//!
//! An attestation document proves a key was generated inside an enclave running a given image.
//! It cannot say whether that key is still trusted, and that is the registry's whole job. So the
//! one thing a lookup must never do is turn a store it could not reach into "unknown key" — that
//! answer is terminal for the caller (§6).
//!
//! [`KeyRegistry`] is the whole database boundary: one row per key, fetched and written whole.
//! `DynamoDB` is the deployed backing ([`DynamoKeyRegistry`]); tests and local runs use
//! [`InMemoryKeyRegistry`].

mod dynamo;
mod memory;
mod public_key;
mod registration;

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::Serialize;

pub use dynamo::DynamoKeyRegistry;
pub use memory::InMemoryKeyRegistry;
pub use public_key::{InvalidSigningPublicKey, SIGNING_PUBLIC_KEY_LEN, SigningPublicKey};
pub use registration::{RegistrationError, register_signing_key, retire_signing_key, verifier};

/// Where a `Signing Key` stands.
///
/// The three answer different questions about a statement the key signed and MUST NOT be
/// collapsed into one another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    /// The enclave is running. Statements it signs are acceptable.
    Active,
    /// The enclave shut down normally. Statements signed before `retired_at` stay acceptable.
    Retired,
    /// The enclave or its image was withdrawn. Every statement this key signed is invalid.
    Revoked,
}

impl KeyStatus {
    /// The stored spelling, which is also what the API serves.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
        }
    }

    /// Reads a stored spelling back.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "active" => Some(Self::Active),
            "retired" => Some(Self::Retired),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// One row of the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEntry {
    /// The key this row is about.
    pub public_key: SigningPublicKey,
    /// The raw COSE document attesting `public_key`. Self-verifying, so it — not this row — is
    /// what makes the key authentic.
    pub attestation: Vec<u8>,
    /// PCR0 as the verified document reported it: the image measurement clients pin.
    pub pcr0: Vec<u8>,
    /// When the key was attested, in seconds since the Unix epoch.
    pub valid_from: u64,
    /// When the enclave shut down, if it has.
    pub retired_at: Option<u64>,
    /// Validity state.
    pub status: KeyStatus,
}

/// Failures while reading or writing the registry.
///
/// Deliberately has no "not found" variant. A miss is `Ok(None)`, so an unreachable store can
/// never be mistaken for a key this `Service` never issued.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// The store could not be reached, or refused the call.
    #[error("key registry is unavailable: {0}")]
    Unavailable(String),
    /// A stored row could not be read back into a [`RegistryEntry`]. Retrying will not fix it.
    #[error("key registry holds a malformed row for {public_key}: {reason}")]
    Malformed {
        /// The key whose row could not be read.
        public_key: SigningPublicKey,
        /// What was wrong with it.
        reason: String,
    },
}

/// The append-only record of every `Signing Key` this `Service` has used.
///
/// A row is read and written whole, which is all the registry needs and all a backing database
/// has to offer to serve as one.
#[async_trait]
pub trait KeyRegistry: Send + Sync {
    /// Reads one key's row. `Ok(None)` means this `Service` never issued it.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] if the store could not be read. A read failure is never a miss.
    async fn get(
        &self,
        public_key: SigningPublicKey,
    ) -> Result<Option<RegistryEntry>, RegistryError>;

    /// Writes `entry`, replacing any row for the same key.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] if the store could not be written.
    async fn set(&self, entry: &RegistryEntry) -> Result<(), RegistryError>;
}

/// Wall-clock seconds since the Unix epoch, saturating at 0 on a clock before it.
pub(crate) fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

#[cfg(test)]
mod tests {
    use super::KeyStatus;

    #[test]
    fn every_status_round_trips_through_its_stored_spelling() {
        for status in [KeyStatus::Active, KeyStatus::Retired, KeyStatus::Revoked] {
            assert_eq!(KeyStatus::parse(status.as_str()), Some(status));
        }
    }

    /// A row whose status the host cannot read must fail loudly rather than default to `active`.
    #[test]
    fn an_unknown_status_does_not_become_active() {
        assert_eq!(KeyStatus::parse("ACTIVE"), None);
        assert_eq!(KeyStatus::parse("expired"), None);
        assert_eq!(KeyStatus::parse(""), None);
    }
}

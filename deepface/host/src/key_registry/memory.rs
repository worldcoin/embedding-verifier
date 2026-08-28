//! In-memory [`KeyRegistry`], for tests and local runs with no AWS account.
//!
//! Boot-scoped: a restart takes the rows with it, so it is not a deployable registry.

use async_trait::async_trait;
use moka::future::Cache;

use super::{KeyRegistry, RegistryEntry, RegistryError, SigningPublicKey};

/// A registry held in memory.
#[derive(Debug, Clone)]
pub struct InMemoryKeyRegistry {
    rows: Cache<SigningPublicKey, RegistryEntry>,
}

impl Default for InMemoryKeyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryKeyRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            // Deliberately unbounded and with no TTL. Evicting a row turns a key this `Service`
            // did issue into a `404`, which is a hard verification failure — a registry must
            // forget nothing while the process lives.
            rows: Cache::builder().build(),
        }
    }
}

#[async_trait]
impl KeyRegistry for InMemoryKeyRegistry {
    async fn get(
        &self,
        public_key: SigningPublicKey,
    ) -> Result<Option<RegistryEntry>, RegistryError> {
        Ok(self.rows.get(&public_key).await)
    }

    async fn set(&self, entry: &RegistryEntry) -> Result<(), RegistryError> {
        self.rows.insert(entry.public_key, entry.clone()).await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::InMemoryKeyRegistry;
    use crate::key_registry::{KeyRegistry, KeyStatus, RegistryEntry, SigningPublicKey};

    fn entry(public_key: SigningPublicKey) -> RegistryEntry {
        RegistryEntry {
            public_key,
            attestation: vec![1, 2, 3],
            pcr0: vec![9; 48],
            valid_from: 1_780_000_000,
            retired_at: None,
            status: KeyStatus::Active,
        }
    }

    #[tokio::test]
    async fn a_key_that_was_never_written_is_a_miss_and_not_an_error() {
        let registry = InMemoryKeyRegistry::new();

        let found = registry
            .get(SigningPublicKey::from_bytes([1; 32]))
            .await
            .expect("a miss is not a failure");

        assert_eq!(found, None);
    }

    #[tokio::test]
    async fn set_then_get_returns_the_row() {
        let registry = InMemoryKeyRegistry::new();
        let key = SigningPublicKey::from_bytes([1; 32]);

        registry.set(&entry(key)).await.expect("should write");

        assert_eq!(
            registry.get(key).await.expect("should read"),
            Some(entry(key))
        );
    }

    #[tokio::test]
    async fn set_replaces_the_row_for_the_same_key() {
        let registry = InMemoryKeyRegistry::new();
        let key = SigningPublicKey::from_bytes([1; 32]);
        registry.set(&entry(key)).await.expect("should write");

        let retired = RegistryEntry {
            retired_at: Some(1_780_000_900),
            status: KeyStatus::Retired,
            ..entry(key)
        };
        registry.set(&retired).await.expect("should write");

        assert_eq!(registry.get(key).await.expect("should read"), Some(retired));
    }
}

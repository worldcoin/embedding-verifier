//! Storage for RP-pushed challenge images.
//!
//! The RP pushes its encrypted challenge frame to `POST /v1/challenges` before handing the
//! returned id to the authenticator, so the host never fetches a caller-supplied URL — the
//! lookup at match time reads a store this service owns. What was an SSRF surface (an egress
//! allowlist, a resolver policy) becomes ingress control: a size cap, a TTL, and a byte budget.
//!
//! The blob is AES-256-GCM ciphertext under a key this service never sees; only the enclave
//! receives that key, sealed inside the match request. Storing it here changes how long the
//! host holds bytes it cannot read, not what it can do with them.
//!
//! TODO(AUTH): the ingest takes any caller. The bounds here limit the abuse to storage churn,
//! but before untrusted exposure `POST /v1/challenges` needs RP authentication.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use tokio::time::Instant;

/// Ceiling on one challenge ciphertext.
pub const MAX_CHALLENGE_BYTES: usize = 4 * 1024 * 1024;

/// How long a stored challenge stays retrievable.
///
/// Sized to a `ProofRequest` lifetime: the RP uploads moments before handing the id to the
/// authenticator, and a match arriving later than this holds a challenge the RP no longer
/// stands behind.
pub const CHALLENGE_TTL: Duration = Duration::from_hours(1);

/// Byte budget for the in-memory store, the backstop against an unauthenticated ingest
/// becoming memory exhaustion.
const MAX_STORE_BYTES: usize = 256 * 1024 * 1024;

/// Length of a challenge id in bytes.
const CHALLENGE_ID_LEN: usize = 16;

/// An opaque, unguessable handle to one stored challenge.
///
/// 128 random bits, so holding an id is holding the capability to name that blob in a match.
/// Substituting someone else's id still fails closed — the blob will not decrypt under the
/// key sealed in the substituted-into request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChallengeId([u8; CHALLENGE_ID_LEN]);

impl ChallengeId {
    /// Generates a fresh random id.
    fn generate() -> Self {
        Self(rand::random())
    }
}

impl fmt::Display for ChallengeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

/// The id was not 32 hex characters.
#[derive(Debug, thiserror::Error)]
#[error("challenge id must be 32 hex characters")]
pub struct InvalidChallengeId;

impl FromStr for ChallengeId {
    type Err = InvalidChallengeId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; CHALLENGE_ID_LEN];
        hex::decode_to_slice(s, &mut bytes).map_err(|_| InvalidChallengeId)?;

        Ok(Self(bytes))
    }
}

/// Failures while reading or writing the store.
///
/// Deliberately has no "not found" variant. A miss is `Ok(None)`, so an unreachable store can
/// never be mistaken for a challenge that was never uploaded — that answer is terminal for the
/// caller, an outage is not.
#[derive(Debug, Clone, thiserror::Error)]
pub enum StoreError {
    /// The store's budget is spent; retry after entries expire.
    #[error("challenge store is full")]
    Full,
    /// The store could not be reached, or refused the call.
    #[error("challenge store is unavailable: {0}")]
    Unavailable(String),
}

/// Where challenge ciphertexts wait between the RP's push and the match that names them.
///
/// A blob is written once and read whole. `get` does not consume: the client's one bounded
/// `409` retry re-seals to a fresh enclave but names the same challenge, so the entry must
/// survive its first read. Expiry is the TTL's job.
#[async_trait]
pub trait ChallengeStore: Send + Sync {
    /// Stores `ciphertext` and returns the id that names it.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the store is full or could not be written.
    async fn put(&self, ciphertext: Vec<u8>) -> Result<ChallengeId, StoreError>;

    /// Reads one challenge. `Ok(None)` means no live entry: never uploaded, or expired.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the store could not be read. A read failure is never a miss.
    async fn get(&self, id: &ChallengeId) -> Result<Option<Vec<u8>>, StoreError>;
}

/// One stored blob and when it arrived.
struct Entry {
    ciphertext: Vec<u8>,
    stored_at: Instant,
}

/// In-memory [`ChallengeStore`] for a single host.
///
/// Development and test only: the RP's push carries no affinity cookie, so in a fleet it lands
/// on a different host than the match, and per-host memory cannot serve that. The shared
/// (S3-backed) implementation is a separate change, the same way the key registry landed.
pub struct InMemoryChallengeStore {
    entries: Mutex<HashMap<ChallengeId, Entry>>,
}

impl InMemoryChallengeStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChallengeStore for InMemoryChallengeStore {
    async fn put(&self, ciphertext: Vec<u8>) -> Result<ChallengeId, StoreError> {
        let now = Instant::now();
        let mut entries = self.entries.lock().expect("challenge store lock poisoned");

        // Expired entries only ever leave on this sweep, so the budget below is measured
        // against live bytes rather than garbage.
        entries.retain(|_, entry| now.duration_since(entry.stored_at) < CHALLENGE_TTL);

        let held: usize = entries.values().map(|entry| entry.ciphertext.len()).sum();
        if held + ciphertext.len() > MAX_STORE_BYTES {
            tracing::warn!(
                held_bytes = held,
                budget_bytes = MAX_STORE_BYTES,
                "challenge store byte budget exhausted"
            );
            return Err(StoreError::Full);
        }

        let id = ChallengeId::generate();
        entries.insert(
            id,
            Entry {
                ciphertext,
                stored_at: now,
            },
        );
        drop(entries);

        Ok(id)
    }

    async fn get(&self, id: &ChallengeId) -> Result<Option<Vec<u8>>, StoreError> {
        let entries = self.entries.lock().expect("challenge store lock poisoned");

        Ok(entries
            .get(id)
            .filter(|entry| Instant::now().duration_since(entry.stored_at) < CHALLENGE_TTL)
            .map(|entry| entry.ciphertext.clone()))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{
        CHALLENGE_TTL, ChallengeId, ChallengeStore, InMemoryChallengeStore, MAX_STORE_BYTES,
        StoreError,
    };

    #[tokio::test]
    async fn put_then_get_round_trips() {
        let store = InMemoryChallengeStore::new();

        let id = store
            .put(b"challenge-ciphertext".to_vec())
            .await
            .expect("put should succeed");

        assert_eq!(
            store.get(&id).await.expect("get should succeed"),
            Some(b"challenge-ciphertext".to_vec())
        );
    }

    #[tokio::test]
    async fn an_unknown_id_is_a_miss_not_an_error() {
        let store = InMemoryChallengeStore::new();
        let id = ChallengeId::from_str("00112233445566778899aabbccddeeff").expect("valid id");

        assert_eq!(store.get(&id).await.expect("get should succeed"), None);
    }

    #[tokio::test]
    async fn ids_are_distinct_per_put() {
        let store = InMemoryChallengeStore::new();

        let first = store.put(b"a".to_vec()).await.expect("put should succeed");
        let second = store.put(b"b".to_vec()).await.expect("put should succeed");

        assert_ne!(first, second);
    }

    #[tokio::test(start_paused = true)]
    async fn entries_expire_after_the_ttl() {
        let store = InMemoryChallengeStore::new();
        let id = store
            .put(b"challenge-ciphertext".to_vec())
            .await
            .expect("put should succeed");

        tokio::time::advance(CHALLENGE_TTL / 2).await;
        assert!(
            store.get(&id).await.expect("get should succeed").is_some(),
            "an entry younger than the TTL must be served"
        );

        tokio::time::advance(CHALLENGE_TTL).await;
        assert_eq!(
            store.get(&id).await.expect("get should succeed"),
            None,
            "an entry older than the TTL must read as a miss"
        );
    }

    #[tokio::test]
    async fn a_put_over_the_byte_budget_is_full() {
        let store = InMemoryChallengeStore::new();
        store
            .put(vec![0u8; MAX_STORE_BYTES])
            .await
            .expect("filling the budget exactly should succeed");

        let error = store.put(b"x".to_vec()).await.expect_err("budget is spent");

        assert!(matches!(error, StoreError::Full));
    }

    #[tokio::test(start_paused = true)]
    async fn expired_entries_free_their_budget() {
        let store = InMemoryChallengeStore::new();
        store
            .put(vec![0u8; MAX_STORE_BYTES])
            .await
            .expect("filling the budget exactly should succeed");

        tokio::time::advance(CHALLENGE_TTL).await;

        assert!(
            store.put(b"x".to_vec()).await.is_ok(),
            "the sweep on put must reclaim expired bytes"
        );
    }

    #[test]
    fn ids_round_trip_through_hex() {
        let id = ChallengeId([7u8; 16]);

        assert_eq!(
            ChallengeId::from_str(&id.to_string()).expect("should parse"),
            id
        );
    }

    #[test]
    fn malformed_ids_do_not_parse() {
        for candidate in [
            "",
            "not hex",
            "0011223344556677",                   // too short
            "00112233445566778899aabbccddeeff00", // too long
        ] {
            assert!(ChallengeId::from_str(candidate).is_err(), "{candidate}");
        }
    }
}

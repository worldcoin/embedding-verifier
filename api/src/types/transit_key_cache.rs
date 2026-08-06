//! Cache for the enclave's attested transit key.

use std::sync::{Arc, RwLock};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use tokio::{
    sync::Mutex,
    time::{Duration, Instant},
};

use crate::enclave::{EnclaveClient, EnclaveClientError};

/// How long a cached attestation may be served.
///
/// A backstop, not the primary bound — liveness is (see [`TransitKeyCache`]). Its job is
/// to stay far inside the 3-hour Nitro leaf-certificate lifetime, so every document this
/// host hands out has most of its validity left when a client checks `notAfter`, and so
/// an enclave restart the host never observed still self-heals.
const MAX_AGE: Duration = Duration::from_mins(15);

/// A cached attestation, held in the form the endpoint serves.
struct CachedAttestation {
    /// Base64 of the raw COSE document — encoded once, so a cache hit does no work.
    encoded: Arc<str>,
    fetched_at: Instant,
}

impl CachedAttestation {
    fn is_fresh(&self, now: Instant) -> bool {
        now.duration_since(self.fetched_at) < MAX_AGE
    }
}

/// Caches the enclave's attested transit key for the lifetime of one enclave boot.
///
/// Attesting is the expensive part of the endpoint and the document is identical between
/// calls — no client nonce is bound into it, because a key-to-image binding is
/// time-invariant and a replayed document therefore states something true. What a cached
/// document *must* not do is outlive the enclave that produced it: the transit key is
/// boot-scoped, so a stale document advertises a key nobody holds and every client that
/// seals to it fails with nothing to diagnose.
///
/// Two things bound staleness:
///
/// * *liveness* — [`Self::invalidate`] is called whenever an enclave call fails at the
///   transport layer. Pontifex opens a fresh vsock connection per request, so there is no
///   long-lived connection whose reconnect could be observed directly; a failed connect
///   is the host's equivalent signal. The readiness probe calls the enclave on every
///   poll, which is what makes that signal continuous rather than incidental.
/// * *age* — [`MAX_AGE`], for the restart that happens to fall between two successful
///   calls.
///
/// Staleness costs availability, not confidentiality: a client that seals to a dead key
/// gets no statement, and an attacker who replays an old document gains nothing it could
/// not obtain by asking.
pub struct TransitKeyCache {
    entry: RwLock<Option<CachedAttestation>>,
    /// Serialises misses so a cold cache under load produces one attestation, not one
    /// per caller.
    refresh: Mutex<()>,
}

impl Default for TransitKeyCache {
    fn default() -> Self {
        Self::new()
    }
}

impl TransitKeyCache {
    /// Creates an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entry: RwLock::new(None),
            refresh: Mutex::new(()),
        }
    }

    /// Returns the base64-encoded attestation, fetching it if there is no fresh entry.
    ///
    /// # Errors
    ///
    /// Propagates the enclave-client failure when the cache is cold and the enclave
    /// cannot be reached. A stale entry is never served in its place: the enclave being
    /// unreachable is precisely when the cached key is most likely to be dead.
    pub async fn encoded_attestation(
        &self,
        client: &dyn EnclaveClient,
    ) -> Result<Arc<str>, EnclaveClientError> {
        if let Some(hit) = self.fresh_entry() {
            return Ok(hit);
        }

        let _refresh = self.refresh.lock().await;

        // Another caller may have refreshed while we waited for the guard.
        if let Some(hit) = self.fresh_entry() {
            return Ok(hit);
        }

        let response = client.get_transit_key().await?;
        let encoded: Arc<str> = Arc::from(STANDARD.encode(response.attestation));

        self.store(CachedAttestation {
            encoded: Arc::clone(&encoded),
            fetched_at: Instant::now(),
        });
        tracing::debug!("refreshed the cached transit-key attestation");

        Ok(encoded)
    }

    /// Drops any cached attestation.
    ///
    /// Cheap and idempotent: the worst case is one extra attestation.
    pub fn invalidate(&self) {
        let dropped = self.take();

        if dropped {
            tracing::warn!("invalidated the cached transit-key attestation");
        }
    }

    fn fresh_entry(&self) -> Option<Arc<str>> {
        let now = Instant::now();
        let guard = self
            .entry
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        guard
            .as_ref()
            .filter(|entry| entry.is_fresh(now))
            .map(|entry| Arc::clone(&entry.encoded))
    }

    fn store(&self, entry: CachedAttestation) {
        let mut guard = self
            .entry
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Some(entry);
    }

    /// Clears the entry, reporting whether there was one.
    fn take(&self) -> bool {
        let mut guard = self
            .entry
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        guard.take().is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use enclave_types::{GetTransitKeyResponse, MatchRequest, MatchResponse};

    use tokio::time::Duration;

    use super::{MAX_AGE, TransitKeyCache};
    use crate::enclave::{EnclaveClient, EnclaveClientError};

    /// Counts attestations and hands out a distinguishable document each time.
    struct CountingEnclaveClient {
        calls: AtomicUsize,
        fail: bool,
    }

    impl CountingEnclaveClient {
        const fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                fail: false,
            }
        }

        const fn failing() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                fail: true,
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl EnclaveClient for CountingEnclaveClient {
        async fn health(&self) -> Result<(), EnclaveClientError> {
            Ok(())
        }

        async fn get_transit_key(&self) -> Result<GetTransitKeyResponse, EnclaveClientError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(EnclaveClientError::Transport("enclave is gone".to_owned()));
            }

            Ok(GetTransitKeyResponse {
                attestation: vec![u8::try_from(call).unwrap_or(u8::MAX)],
            })
        }

        async fn run_match(&self, _: MatchRequest) -> Result<MatchResponse, EnclaveClientError> {
            unreachable!("the cache never runs a match")
        }
    }

    #[tokio::test]
    async fn attests_once_and_serves_the_cached_document() {
        let cache = TransitKeyCache::new();
        let client = CountingEnclaveClient::new();

        let first = cache
            .encoded_attestation(&client)
            .await
            .expect("should fetch");
        let second = cache
            .encoded_attestation(&client)
            .await
            .expect("should hit");

        assert_eq!(first, second);
        assert_eq!(client.calls(), 1);
    }

    #[tokio::test]
    async fn invalidation_forces_a_fresh_attestation() {
        let cache = TransitKeyCache::new();
        let client = CountingEnclaveClient::new();
        let first = cache
            .encoded_attestation(&client)
            .await
            .expect("should fetch");

        cache.invalidate();
        let second = cache
            .encoded_attestation(&client)
            .await
            .expect("should refetch");

        assert_ne!(first, second);
        assert_eq!(client.calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn an_entry_is_not_served_past_its_maximum_age() {
        let cache = TransitKeyCache::new();
        let client = CountingEnclaveClient::new();
        cache
            .encoded_attestation(&client)
            .await
            .expect("should fetch");

        tokio::time::advance(MAX_AGE.saturating_sub(Duration::from_secs(1))).await;
        cache
            .encoded_attestation(&client)
            .await
            .expect("should hit");
        assert_eq!(client.calls(), 1);

        tokio::time::advance(Duration::from_secs(2)).await;
        cache
            .encoded_attestation(&client)
            .await
            .expect("should refetch");
        assert_eq!(client.calls(), 2);
    }

    #[tokio::test]
    async fn concurrent_misses_produce_one_attestation() {
        let cache = Arc::new(TransitKeyCache::new());
        let client = Arc::new(CountingEnclaveClient::new());

        let mut handles = Vec::new();
        for _ in 0..16 {
            let cache = Arc::clone(&cache);
            let client = Arc::clone(&client);
            handles.push(tokio::spawn(async move {
                cache
                    .encoded_attestation(client.as_ref())
                    .await
                    .expect("should fetch")
            }));
        }

        let mut documents = Vec::new();
        for handle in handles {
            documents.push(handle.await.expect("task should not panic"));
        }

        assert!(documents.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!(client.calls(), 1);
    }

    #[tokio::test]
    async fn a_failed_fetch_is_propagated_rather_than_cached() {
        let cache = TransitKeyCache::new();
        let client = CountingEnclaveClient::failing();

        assert!(cache.encoded_attestation(&client).await.is_err());
        assert!(cache.encoded_attestation(&client).await.is_err());
        assert_eq!(client.calls(), 2);
    }
}

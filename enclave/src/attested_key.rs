//! A public key together with a cached attestation document for it.
//!
//! Attesting costs a blocking NSM ioctl, and the assignment route is nothing but that call — which
//! is also exactly where a restart-driven re-assignment burst lands, on a two-vCPU runtime. So the
//! document is cached and refreshed ahead of use (see [`crate::attestation_refresh`]) rather than
//! produced per request.
//!
//! The cache is boot-scoped by construction: it holds a document binding a key generated once at
//! boot, inside the process that generated it. There is nothing to invalidate, because a restart
//! takes the cache with it. What a document *does* outlive is the freshness window clients enforce,
//! so the cache is bounded by age rather than by the boot.

use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use enclave_types::EnclaveError;

use crate::attestation::Attestor;

/// How often each key is re-attested.
///
/// Six documents an hour per key, whatever the request rate, since reads never reach the NSM.
pub const REFRESH_INTERVAL: Duration = Duration::from_mins(10);

/// The oldest document that may still be handed to a client.
///
/// Three refresh intervals, so two consecutive failures are absorbed before requests start failing.
/// Past it [`AttestedKey::document`] reports [`EnclaveError::NotReady`] instead of serving a
/// document the client's own freshness check would reject — an NSM outage has to surface as an
/// enclave error, not as a verification failure on the far side.
///
/// This is a floor on client configuration: a `max_attestation_age_millis` below it can reject a
/// document this enclave still considers servable.
pub const MAX_SERVED_AGE: Duration = Duration::from_mins(30);

/// A document and the instant it was produced.
struct Cached {
    document: Vec<u8>,
    attested_at: Instant,
}

/// A boot-scoped public key and its most recent attestation document.
pub struct AttestedKey {
    attestor: Arc<dyn Attestor>,
    public_key: Vec<u8>,
    max_served_age: Duration,
    cached: RwLock<Cached>,
}

impl AttestedKey {
    /// Attests `public_key` immediately, so a broken NSM fails construction rather than the first
    /// request that needs a document.
    ///
    /// # Errors
    ///
    /// Propagates the [`Attestor`] failure.
    pub fn attest_now(
        attestor: Arc<dyn Attestor>,
        public_key: Vec<u8>,
        max_served_age: Duration,
    ) -> Result<Self, EnclaveError> {
        let document = attestor.attest_public_key(&public_key)?;

        Ok(Self {
            attestor,
            public_key,
            max_served_age,
            cached: RwLock::new(Cached {
                document,
                attested_at: Instant::now(),
            }),
        })
    }

    /// The cached document, if it is still young enough to hand out.
    ///
    /// # Errors
    ///
    /// [`EnclaveError::NotReady`] once the cached document has aged past `max_served_age`.
    pub fn document(&self) -> Result<Vec<u8>, EnclaveError> {
        let cached = self.cached.read().unwrap_or_else(PoisonError::into_inner);

        if cached.attested_at.elapsed() >= self.max_served_age {
            return Err(EnclaveError::NotReady);
        }

        Ok(cached.document.clone())
    }

    /// Re-attests the key and replaces the cached document.
    ///
    /// The NSM call runs outside the lock, so readers never wait on it, and a failure leaves the
    /// previous document in place for callers still inside `max_served_age`.
    ///
    /// # Errors
    ///
    /// Propagates the [`Attestor`] failure.
    pub fn refresh(&self) -> Result<(), EnclaveError> {
        let document = self.attestor.attest_public_key(&self.public_key)?;
        let attested_at = Instant::now();

        let mut cached = self.cached.write().unwrap_or_else(PoisonError::into_inner);
        *cached = Cached {
            document,
            attested_at,
        };
        drop(cached);

        Ok(())
    }

    /// How long ago the cached document was produced.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.cached
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .attested_at
            .elapsed()
    }

    /// Whether the cached document is still young enough to hand out.
    #[must_use]
    pub fn is_servable(&self) -> bool {
        self.age() < self.max_served_age
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use enclave_types::EnclaveError;

    use super::AttestedKey;
    use crate::attestation::Attestor;
    use crate::test_support::{CountingAttestor, FailingAttestor};

    const KEY: &[u8] = b"a-public-key";

    /// A key whose documents never age out during a test.
    fn fresh(attestor: Arc<dyn Attestor>) -> AttestedKey {
        AttestedKey::attest_now(attestor, KEY.to_vec(), Duration::from_hours(1))
            .expect("the attestor should produce a document")
    }

    #[test]
    fn reads_are_served_from_the_cache() {
        let attestor = Arc::new(CountingAttestor::new());
        let key = fresh(Arc::clone(&attestor) as Arc<dyn Attestor>);

        let first = key.document().expect("a fresh document should be servable");
        let second = key.document().expect("a fresh document should be servable");

        assert_eq!(first, second);
        // One call, at construction. Reads must not reach the NSM.
        assert_eq!(attestor.calls(), 1);
    }

    #[test]
    fn refresh_replaces_the_cached_document() {
        let attestor = Arc::new(CountingAttestor::new());
        let key = fresh(Arc::clone(&attestor) as Arc<dyn Attestor>);
        let before = key.document().expect("should be servable");

        key.refresh().expect("refresh should succeed");

        assert_ne!(key.document().expect("should be servable"), before);
        assert_eq!(attestor.calls(), 2);
    }

    /// The ceiling is what keeps an NSM outage from turning into client-side verification failures.
    #[test]
    fn a_document_past_the_ceiling_is_not_served() {
        let key = AttestedKey::attest_now(
            Arc::new(CountingAttestor::new()),
            KEY.to_vec(),
            Duration::ZERO,
        )
        .expect("construction still attests");

        assert_eq!(key.document(), Err(EnclaveError::NotReady));
        assert!(!key.is_servable());
    }

    #[test]
    fn a_failing_attestor_fails_construction() {
        let error = AttestedKey::attest_now(
            Arc::new(FailingAttestor),
            KEY.to_vec(),
            Duration::from_hours(1),
        )
        .err();

        assert_eq!(error, Some(EnclaveError::AttestationFailed));
    }

    /// A failed refresh must not empty the cache: callers inside the ceiling keep being served.
    #[test]
    fn a_failed_refresh_keeps_the_previous_document() {
        let attestor = Arc::new(CountingAttestor::failing_after(1));
        let key = fresh(Arc::clone(&attestor) as Arc<dyn Attestor>);
        let before = key.document().expect("should be servable");

        assert_eq!(key.refresh(), Err(EnclaveError::AttestationFailed));

        assert_eq!(key.document().expect("should still be servable"), before);
    }
}

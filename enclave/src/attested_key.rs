//! A public key and its cached attestation document.
//!
//! Attesting is a blocking NSM ioctl, and the assignment route is nothing but that call — which is
//! where a restart-driven re-assignment burst lands. So documents are cached and refreshed ahead of
//! use by [`crate::attestation_refresh`]. The cache is boot-scoped by construction, so a restart
//! takes it along and there is nothing to invalidate; what a document outlives is the freshness
//! window clients enforce, hence the age bound.

use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use enclave_types::EnclaveError;

use crate::attestation::Attestor;

/// How often each key is re-attested.
pub const REFRESH_INTERVAL: Duration = Duration::from_mins(10);

/// Oldest document still handed out.
///
/// Three refresh intervals, so two failed refreshes are absorbed. Serving past it would hand a
/// client a document its own freshness check rejects, turning an NSM outage into a client-side
/// verification failure. Also a floor on client `max_attestation_age_millis`.
pub const MAX_SERVED_AGE: Duration = Duration::from_mins(30);

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
    /// Attests `public_key` now, so a broken NSM fails construction rather than the first request.
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

    /// The cached document, if still young enough to hand out.
    ///
    /// # Errors
    ///
    /// [`EnclaveError::NotReady`] past `max_served_age`.
    pub fn document(&self) -> Result<Vec<u8>, EnclaveError> {
        let cached = self.cached.read().unwrap_or_else(PoisonError::into_inner);

        if cached.attested_at.elapsed() >= self.max_served_age {
            return Err(EnclaveError::NotReady);
        }

        Ok(cached.document.clone())
    }

    /// Re-attests and replaces the cached document.
    ///
    /// Attests outside the lock, so readers never wait on the ioctl.
    ///
    /// # Errors
    ///
    /// Propagates the [`Attestor`] failure, leaving the previous document in place.
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

    /// Whether the cached document is still young enough to hand out.
    #[must_use]
    pub fn is_servable(&self) -> bool {
        self.cached
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .attested_at
            .elapsed()
            < self.max_served_age
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use enclave_types::EnclaveError;

    use super::AttestedKey;
    use crate::attestation::Attestor;
    use crate::test_support::{CountingAttestor, EchoAttestor};

    fn key(attestor: Arc<dyn Attestor>, max_served_age: Duration) -> AttestedKey {
        AttestedKey::attest_now(attestor, b"a-public-key".to_vec(), max_served_age)
            .expect("should attest")
    }

    #[test]
    fn reads_do_not_reach_the_attestor() {
        let attestor = Arc::new(CountingAttestor::new());
        let cached = key(attestor.clone(), Duration::from_hours(1));

        assert_eq!(cached.document(), cached.document());
        assert_eq!(attestor.calls(), 1, "only the one at construction");
    }

    #[test]
    fn refresh_replaces_the_document() {
        let cached = key(Arc::new(CountingAttestor::new()), Duration::from_hours(1));
        let before = cached.document();

        cached.refresh().expect("should refresh");

        assert_ne!(cached.document(), before);
    }

    /// The ceiling is what keeps an NSM outage from surfacing as a client-side verification failure.
    #[test]
    fn a_document_past_the_ceiling_is_withheld() {
        let cached = key(Arc::new(EchoAttestor), Duration::ZERO);

        assert!(!cached.is_servable());
        assert_eq!(cached.document(), Err(EnclaveError::NotReady));
    }
}

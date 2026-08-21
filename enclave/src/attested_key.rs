//! A public key and its cached attestation document.
//!
//! Attesting is a blocking NSM ioctl, and the assignment route is nothing but that call — which is
//! where a restart-driven re-assignment burst lands. Caching it takes the ioctl off all but one
//! request per interval. The cache is boot-scoped by construction, so a restart takes it along and
//! there is nothing to invalidate; what a document outlives is the freshness window clients
//! enforce, hence the age bound.

use std::sync::Arc;
use std::time::{Duration, Instant};

use enclave_types::EnclaveError;
use tokio::sync::Mutex;

use crate::attestation::Attestor;

/// How long a document is served before the next read re-attests.
///
/// Well inside the hour that `client`'s default `max_attestation_age_millis` allows, so a document
/// is never close to stale when a client verifies it.
pub const MAX_CACHED_AGE: Duration = Duration::from_mins(10);

struct Cached {
    document: Vec<u8>,
    attested_at: Instant,
}

/// A boot-scoped public key and its most recent attestation document.
pub struct AttestedKey {
    attestor: Arc<dyn Attestor>,
    public_key: Vec<u8>,
    max_age: Duration,
    cached: Mutex<Cached>,
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
        max_age: Duration,
    ) -> Result<Self, EnclaveError> {
        let document = attestor.attest_public_key(&public_key)?;

        Ok(Self {
            attestor,
            public_key,
            max_age,
            cached: Mutex::new(Cached {
                document,
                attested_at: Instant::now(),
            }),
        })
    }

    /// A document no older than `max_age`, re-attesting first if the cached one has expired.
    ///
    /// The lock spans check-and-attest, so a burst arriving on an expired document costs one
    /// attestation rather than one per caller. A failure leaves the previous document in place for
    /// the next read to retry.
    ///
    /// # Errors
    ///
    /// Propagates the [`Attestor`] failure.
    pub async fn document(&self) -> Result<Vec<u8>, EnclaveError> {
        let mut cached = self.cached.lock().await;

        if cached.attested_at.elapsed() >= self.max_age {
            cached.document = self.attestor.attest_public_key(&self.public_key)?;
            cached.attested_at = Instant::now();
        }

        Ok(cached.document.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::AttestedKey;
    use crate::attestation::Attestor;
    use crate::test_support::CountingAttestor;

    fn key(attestor: Arc<dyn Attestor>, max_age: Duration) -> AttestedKey {
        AttestedKey::attest_now(attestor, b"a-public-key".to_vec(), max_age).expect("should attest")
    }

    #[tokio::test]
    async fn reads_inside_the_window_do_not_reach_the_attestor() {
        let attestor = Arc::new(CountingAttestor::new());
        let cached = key(attestor.clone(), Duration::from_hours(1));

        assert_eq!(cached.document().await, cached.document().await);
        assert_eq!(attestor.calls(), 1, "only the one at construction");
    }

    #[tokio::test]
    async fn an_expired_document_is_re_attested_before_it_is_served() {
        let attestor = Arc::new(CountingAttestor::new());
        let cached = key(attestor.clone(), Duration::ZERO);

        assert_ne!(cached.document().await, cached.document().await);
        assert_eq!(attestor.calls(), 3, "construction plus one per read");
    }
}

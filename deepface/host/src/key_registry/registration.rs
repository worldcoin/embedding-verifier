//! Putting this boot's `Signing Key` into the registry, and taking it out again.
//!
//! §7.1: the host reads the enclave's signing-key attestation and appends it. Until that lands
//! no verifier can check a statement this enclave signs, so readiness stays red until it does.
//!
//! The enclave sidecar can restart on its own — the host container is a separate process in the
//! same pod and keeps running. A fresh enclave boot attests a fresh key, so registration keeps
//! polling after it first lands and re-registers whenever the attested key changes, retiring the
//! row it replaces. Without this, readiness would keep reporting the pod ready on the strength of
//! a key no enclave can still sign with.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use attested_channel::nitro::{
    EnclaveAttestationError, EnclaveAttestationVerifier, PcrMeasurement, VerifiedAttestation,
};
use backon::{ExponentialBuilder, Retryable as _};
use tokio::sync::watch;

use super::{
    InvalidSigningPublicKey, KeyRegistry, KeyStatus, RegistryEntry, RegistryError,
    SigningPublicKey, unix_seconds,
};
use crate::enclave::{EnclaveClient, EnclaveClientError};

/// How old the enclave's attestation document may be when the host registers it.
///
/// The enclave serves from a cache it refreshes every 10 minutes and abandons at an hour, so this
/// matches the age past which the enclave takes itself down anyway.
const MAX_ATTESTATION_AGE: Duration = Duration::from_hours(1);

/// Wait before the first retry.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
/// Cap on the wait between attempts. Registration is a boot step, not a request path, so a
/// minute between attempts costs nothing but keeps a wedged store from being hammered.
const MAX_BACKOFF: Duration = Duration::from_mins(1);

/// How often to re-check the enclave's attested key after the first registration lands.
///
/// The enclave answers from its attestation cache, not a fresh NSM call, so this is a cheap vsock
/// round trip. Matches the readiness probe's default period, so a sidecar-only enclave restart is
/// caught about as fast as `/ready` polls.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(10);

/// Why this boot's key is not in the registry.
#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    /// The enclave did not answer with its signing-key attestation.
    #[error("enclave did not return the signing-key attestation: {0:?}")]
    Enclave(EnclaveClientError),
    /// The document did not verify against the pinned root and measurements.
    #[error("signing-key attestation did not verify: {0}")]
    Attestation(#[from] EnclaveAttestationError),
    /// The attested `public_key` was not a `BabyJubJub` signing key.
    #[error("attested public key is not a signing key: {0}")]
    PublicKey(#[from] InvalidSigningPublicKey),
    /// The verified document carried no PCR0, which clients pin.
    #[error("verified attestation carries no PCR0")]
    MissingPcr0,
    /// The registry could not be read or written.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// Asked to retire a key the registry has never seen.
    #[error("{0} is not in the registry")]
    NotRegistered(SigningPublicKey),
    /// The registry already holds this key as retired or revoked. Nothing the enclave signs with
    /// it can be verified, and rewriting the row `active` would undo an operator's decision.
    #[error("{public_key} is in the registry as {}", status.as_str())]
    NotActive {
        /// The key the enclave attested.
        public_key: SigningPublicKey,
        /// What the registry says about it.
        status: KeyStatus,
    },
}

/// Builds the verifier the host checks its own enclave against.
///
/// `pcr0` is the measurement of the image this host was deployed with, so an enclave running
/// anything else never reaches the registry.
#[must_use]
pub fn verifier(pcr0: Vec<u8>, allow_debug_measurements: bool) -> EnclaveAttestationVerifier {
    let verifier = EnclaveAttestationVerifier::new(
        vec![vec![PcrMeasurement::new(0, pcr0)]],
        u64::try_from(MAX_ATTESTATION_AGE.as_millis()).unwrap_or(u64::MAX),
    );

    if allow_debug_measurements {
        return verifier.allowing_debug_measurements();
    }

    verifier
}

/// Keeps this boot's signing key registered for as long as the host runs.
///
/// Registers on first success, publishing it on `registered`, then keeps polling the enclave's
/// attested key and re-registers whenever it changes — the enclave sidecar can reboot without the
/// host, which attests a new key the registry has never seen. Never returns.
pub async fn register_signing_key(
    enclave_client: Arc<dyn EnclaveClient>,
    registry: Arc<dyn KeyRegistry>,
    verifier: EnclaveAttestationVerifier,
    registered: watch::Sender<Option<SigningPublicKey>>,
) {
    let mut current: Option<SigningPublicKey> = None;

    loop {
        // The two phases want opposite things from a failure. With nothing registered the host
        // serves no traffic, so a wedged registry should be backed off hard. Once a key is live
        // the cost reverses: every second spent retrying is a second of serving on a key the
        // registry may no longer describe, so one attempt per tick and the next tick is the
        // retry. Backing off here would stretch that window to the cap.
        let result = if current.is_none() {
            let mut failures: u32 = 0;

            (|| register_once(enclave_client.as_ref(), registry.as_ref(), &verifier))
                .retry(backoff())
                .notify(|error, delay| {
                    failures = failures.saturating_add(1);
                    tracing::warn!(
                        %error,
                        attempt = failures,
                        retry_in = ?delay,
                        dependency = "key-registry",
                        "could not confirm this boot's signing key is registered; readiness stays red"
                    );
                })
                .await
        } else {
            register_once(enclave_client.as_ref(), registry.as_ref(), &verifier).await
        };

        match result {
            Ok(public_key) => {
                reconcile(registry.as_ref(), &mut current, public_key, &registered).await;
            }
            // Retired or revoked is a decision, not an outage: no retry will change it, and
            // nothing this enclave signs can be verified while it stands. Serving on the key
            // published before would be reporting healthy on exactly the thing that is wrong.
            Err(error @ RegistrationError::NotActive { .. }) => {
                tracing::error!(
                    %error,
                    dependency = "key-registry",
                    "the enclave's signing key is not active in the registry; taking this host out of service"
                );
                current = None;
                let _ = registered.send(None);
            }
            Err(error) => tracing::warn!(
                %error,
                dependency = "key-registry",
                "could not confirm the enclave's signing key is registered; retrying on the next poll"
            ),
        }

        tokio::time::sleep(RECONCILE_INTERVAL).await;
    }
}

/// Publishes `attested_key` if it differs from `current`, retiring the row it replaces.
///
/// A changed key means the enclave this host talks to rebooted on its own: whatever held
/// `current` is gone, so its row is retired rather than left `active` for a key nothing can still
/// sign with. Retirement is best-effort, matching the graceful-shutdown path in `server.rs`: a
/// failure here leaves a stale row `active`, which is wrong but not unsafe.
async fn reconcile(
    registry: &dyn KeyRegistry,
    current: &mut Option<SigningPublicKey>,
    attested_key: SigningPublicKey,
    registered: &watch::Sender<Option<SigningPublicKey>>,
) {
    if *current == Some(attested_key) {
        return;
    }

    if let Some(previous) = current.replace(attested_key) {
        tracing::warn!(
            previous = %previous,
            public_key = %attested_key,
            "enclave's attested signing key changed; retiring the previous boot's key"
        );

        if let Err(error) = retire_signing_key(registry, previous, unix_seconds()).await {
            tracing::warn!(
                %error,
                public_key = %previous,
                dependency = "key-registry",
                "failed to retire the signing key this boot replaced; it stays active in the registry"
            );
        }
    } else {
        tracing::info!(%attested_key, "registered this boot's signing key");
    }

    // The receiver lives in the app state, which outlives this task.
    let _ = registered.send(*current);
}

/// Retry schedule for registration: exponential with jitter, and no cap on attempts.
///
/// Nothing else reports this host ready, so giving up would take it out of the load balancer for
/// good. Backing off to a minute and staying there is what a wedged registry should cost.
const fn backoff() -> ExponentialBuilder {
    ExponentialBuilder::new()
        .with_min_delay(INITIAL_BACKOFF)
        .with_max_delay(MAX_BACKOFF)
        .with_jitter()
        .without_max_times()
}

/// Records that the enclave holding `public_key` shut down normally.
///
/// A `revoked` or already-`retired` row is left alone: retirement is informational, and it must
/// not walk a revocation back. Read-modify-write, so a revocation landing between the two calls
/// would be lost — a race worth closing with a conditional write if revocation ever becomes
/// anything but a rare operator action.
///
/// # Errors
///
/// Returns [`RegistrationError`] if the registry could not be read or written, or if the key was
/// never registered.
pub async fn retire_signing_key(
    registry: &dyn KeyRegistry,
    public_key: SigningPublicKey,
    retired_at: u64,
) -> Result<(), RegistrationError> {
    let entry = registry
        .get(public_key)
        .await?
        .ok_or(RegistrationError::NotRegistered(public_key))?;

    if entry.status != KeyStatus::Active {
        tracing::info!(
            %public_key,
            status = entry.status.as_str(),
            "signing key was not active; left as it stands"
        );
        return Ok(());
    }

    registry
        .set(&RegistryEntry {
            retired_at: Some(retired_at),
            status: KeyStatus::Retired,
            ..entry
        })
        .await
        .map_err(RegistrationError::Registry)
}

/// One attempt: fetch the attestation, verify it, write the row it describes.
async fn register_once(
    enclave_client: &dyn EnclaveClient,
    registry: &dyn KeyRegistry,
    verifier: &EnclaveAttestationVerifier,
) -> Result<SigningPublicKey, RegistrationError> {
    let document = enclave_client
        .signing_key_attestation()
        .await
        .map_err(RegistrationError::Enclave)?;

    let attestation = verifier.verify(&document, SystemTime::now())?;
    let entry = entry_from(document, &attestation)?;
    let public_key = entry.public_key;

    ensure_registered(registry, &entry).await?;

    Ok(public_key)
}

/// Writes `entry` only if the registry does not already hold that key.
///
/// Written once, not on every poll. A key already in the registry is either still active, which
/// this has nothing to add to, or it is retired or revoked — and writing it back `active` would
/// undo the only claim the registry exists to make, within one poll and saying nothing about it.
async fn ensure_registered(
    registry: &dyn KeyRegistry,
    entry: &RegistryEntry,
) -> Result<(), RegistrationError> {
    match registry.get(entry.public_key).await? {
        None => registry
            .set(entry)
            .await
            .map_err(RegistrationError::Registry),
        Some(existing) if existing.status == KeyStatus::Active => Ok(()),
        Some(existing) => Err(RegistrationError::NotActive {
            public_key: entry.public_key,
            status: existing.status,
        }),
    }
}

/// Builds the row from the *verified* document, never from anything the host chose.
fn entry_from(
    document: Vec<u8>,
    verified: &VerifiedAttestation,
) -> Result<RegistryEntry, RegistrationError> {
    let public_key = SigningPublicKey::try_from(verified.enclave_public_key.as_slice())?;
    let pcr0 = verified
        .pcrs
        .get(&0)
        .cloned()
        .ok_or(RegistrationError::MissingPcr0)?;

    Ok(RegistryEntry {
        public_key,
        attestation: document,
        pcr0,
        // The document's own timestamp, not the host's clock: it is signed, and it is when the
        // key was actually attested rather than when this task got round to writing it.
        valid_from: verified.timestamp_millis / 1_000,
        retired_at: None,
        status: KeyStatus::Active,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    use attested_channel::nitro::VerifiedAttestation;
    use tokio::sync::watch;

    use super::{
        RegistrationError, ensure_registered, entry_from, reconcile, register_signing_key,
        retire_signing_key,
    };
    use crate::key_registry::{
        InMemoryKeyRegistry, KeyRegistry, KeyStatus, RegistryEntry, SigningPublicKey,
    };

    fn verified(public_key: Vec<u8>, pcr0: Option<Vec<u8>>) -> VerifiedAttestation {
        VerifiedAttestation {
            enclave_public_key: public_key,
            module_id: "i-0abc-enc0123".to_owned(),
            timestamp_millis: 1_780_000_000_500,
            pcrs: pcr0
                .map(|value| BTreeMap::from([(0, value)]))
                .unwrap_or_default(),
        }
    }

    #[test]
    fn a_row_takes_every_field_from_the_verified_document() {
        let entry = entry_from(vec![1, 2, 3], &verified(vec![7; 32], Some(vec![9; 48])))
            .expect("should build a row");

        assert_eq!(entry.public_key, SigningPublicKey::from_bytes([7; 32]));
        assert_eq!(entry.attestation, vec![1, 2, 3]);
        assert_eq!(entry.pcr0, vec![9; 48]);
        assert_eq!(entry.valid_from, 1_780_000_000);
        assert_eq!(entry.retired_at, None);
        assert_eq!(entry.status, KeyStatus::Active);
    }

    #[test]
    fn a_document_without_pcr0_does_not_register() {
        let error = entry_from(vec![1], &verified(vec![7; 32], None))
            .expect_err("clients pin PCR0, so a row without one is useless");

        assert!(matches!(error, RegistrationError::MissingPcr0));
    }

    #[test]
    fn an_attested_key_of_the_wrong_length_does_not_register() {
        let error = entry_from(vec![1], &verified(vec![7; 31], Some(vec![9; 48])))
            .expect_err("a 31-byte key is not a BabyJubJub signing key");

        assert!(matches!(error, RegistrationError::PublicKey(_)));
    }

    fn entry(public_key: SigningPublicKey, status: KeyStatus) -> RegistryEntry {
        RegistryEntry {
            public_key,
            attestation: vec![1, 2, 3],
            pcr0: vec![9; 48],
            valid_from: 1_780_000_000,
            retired_at: None,
            status,
        }
    }

    #[tokio::test]
    async fn retiring_an_active_key_records_when_it_stopped() {
        let registry = InMemoryKeyRegistry::new();
        let key = SigningPublicKey::from_bytes([7; 32]);
        registry
            .set(&entry(key, KeyStatus::Active))
            .await
            .expect("should write");

        retire_signing_key(&registry, key, 1_780_000_900)
            .await
            .expect("should retire");

        let stored = registry
            .get(key)
            .await
            .expect("should read")
            .expect("a row");
        assert_eq!(stored.status, KeyStatus::Retired);
        assert_eq!(stored.retired_at, Some(1_780_000_900));
    }

    /// Every statement a revoked key signed is invalid. A normal shutdown must not soften that
    /// into "acceptable before `retired_at`".
    #[tokio::test]
    async fn retiring_does_not_walk_back_a_revocation() {
        let registry = InMemoryKeyRegistry::new();
        let key = SigningPublicKey::from_bytes([7; 32]);
        registry
            .set(&entry(key, KeyStatus::Revoked))
            .await
            .expect("should write");

        retire_signing_key(&registry, key, 1_780_000_900)
            .await
            .expect("leaving it alone is success");

        let stored = registry
            .get(key)
            .await
            .expect("should read")
            .expect("a row");
        assert_eq!(stored.status, KeyStatus::Revoked);
        assert_eq!(stored.retired_at, None);
    }

    #[tokio::test]
    async fn retiring_a_key_that_was_never_registered_is_an_error() {
        let registry = InMemoryKeyRegistry::new();

        let error = retire_signing_key(&registry, SigningPublicKey::from_bytes([7; 32]), 1)
            .await
            .expect_err("there is nothing to retire");

        assert!(matches!(error, RegistrationError::NotRegistered(_)));
    }

    #[tokio::test]
    async fn reconcile_publishes_the_first_key_without_retiring_anything() {
        let registry = InMemoryKeyRegistry::new();
        let key = SigningPublicKey::from_bytes([1; 32]);
        registry
            .set(&entry(key, KeyStatus::Active))
            .await
            .expect("should write");
        let mut current = None;
        let (sender, receiver) = watch::channel(None);

        reconcile(&registry, &mut current, key, &sender).await;

        assert_eq!(current, Some(key));
        assert_eq!(*receiver.borrow(), Some(key));
    }

    #[tokio::test]
    async fn reconcile_does_nothing_when_the_attested_key_has_not_changed() {
        let registry = InMemoryKeyRegistry::new();
        let key = SigningPublicKey::from_bytes([1; 32]);
        registry
            .set(&entry(key, KeyStatus::Active))
            .await
            .expect("should write");
        let mut current = Some(key);
        let (sender, receiver) = watch::channel(None);

        reconcile(&registry, &mut current, key, &sender).await;

        assert_eq!(current, Some(key));
        assert_eq!(
            *receiver.borrow(),
            None,
            "nothing is published when the key did not change"
        );
        let stored = registry
            .get(key)
            .await
            .expect("should read")
            .expect("a row");
        assert_eq!(
            stored.status,
            KeyStatus::Active,
            "an unchanged key must not be retired"
        );
    }

    /// Catches an enclave sidecar that rebooted without the host: the new boot's key was already
    /// registered active by `register_once`, and reconciliation must retire the row it replaced.
    #[tokio::test]
    async fn reconcile_retires_the_replaced_key_and_publishes_the_new_one() {
        let registry = InMemoryKeyRegistry::new();
        let old_key = SigningPublicKey::from_bytes([1; 32]);
        let new_key = SigningPublicKey::from_bytes([2; 32]);
        registry
            .set(&entry(old_key, KeyStatus::Active))
            .await
            .expect("should write");
        registry
            .set(&entry(new_key, KeyStatus::Active))
            .await
            .expect("should write");
        let mut current = Some(old_key);
        let (sender, receiver) = watch::channel(None);

        reconcile(&registry, &mut current, new_key, &sender).await;

        assert_eq!(current, Some(new_key));
        assert_eq!(
            *receiver.borrow(),
            Some(new_key),
            "readiness must see the enclave's live key, not the stale one"
        );
        let old_row = registry
            .get(old_key)
            .await
            .expect("should read")
            .expect("a row");
        assert_eq!(
            old_row.status,
            KeyStatus::Retired,
            "the enclave that held the old key is gone"
        );
    }

    /// The reconcile loop re-runs registration every poll. Rewriting the row each time would
    /// undo a revocation within one interval, which is the one thing the registry is for.
    #[tokio::test]
    async fn registering_does_not_walk_back_a_revocation() {
        let registry = InMemoryKeyRegistry::new();
        let key = SigningPublicKey::from_bytes([7; 32]);
        registry
            .set(&entry(key, KeyStatus::Revoked))
            .await
            .expect("should write");

        let error = ensure_registered(&registry, &entry(key, KeyStatus::Active))
            .await
            .expect_err("a revoked key must not be re-registered as active");

        assert!(matches!(
            error,
            RegistrationError::NotActive {
                status: KeyStatus::Revoked,
                ..
            }
        ));
        let stored = registry
            .get(key)
            .await
            .expect("should read")
            .expect("a row");
        assert_eq!(stored.status, KeyStatus::Revoked);
    }

    /// Same for a retired row: the enclave that held the key is gone, and a poll saying
    /// otherwise would resurrect it.
    #[tokio::test]
    async fn registering_does_not_resurrect_a_retired_key() {
        let registry = InMemoryKeyRegistry::new();
        let key = SigningPublicKey::from_bytes([7; 32]);
        registry
            .set(&RegistryEntry {
                retired_at: Some(1_780_000_900),
                ..entry(key, KeyStatus::Retired)
            })
            .await
            .expect("should write");

        let error = ensure_registered(&registry, &entry(key, KeyStatus::Active))
            .await
            .expect_err("a retired key must not be re-registered as active");

        assert!(matches!(
            error,
            RegistrationError::NotActive {
                status: KeyStatus::Retired,
                ..
            }
        ));
        let stored = registry
            .get(key)
            .await
            .expect("should read")
            .expect("a row");
        assert_eq!(stored.status, KeyStatus::Retired);
        assert_eq!(stored.retired_at, Some(1_780_000_900));
    }

    #[tokio::test]
    async fn registering_writes_a_key_the_registry_has_never_seen() {
        let registry = InMemoryKeyRegistry::new();
        let key = SigningPublicKey::from_bytes([7; 32]);

        ensure_registered(&registry, &entry(key, KeyStatus::Active))
            .await
            .expect("a new key should be written");

        let stored = registry
            .get(key)
            .await
            .expect("should read")
            .expect("a row");
        assert_eq!(stored.status, KeyStatus::Active);
    }

    /// Polling an already-active key must not rewrite it — the row carries the attestation and
    /// `valid_from` from the boot that made it, and a poll has nothing newer to say.
    #[tokio::test]
    async fn registering_an_active_key_again_leaves_the_row_alone() {
        let registry = InMemoryKeyRegistry::new();
        let key = SigningPublicKey::from_bytes([7; 32]);
        registry
            .set(&RegistryEntry {
                valid_from: 1_780_000_000,
                ..entry(key, KeyStatus::Active)
            })
            .await
            .expect("should write");

        ensure_registered(
            &registry,
            &RegistryEntry {
                valid_from: 1_999_999_999,
                ..entry(key, KeyStatus::Active)
            },
        )
        .await
        .expect("an active key needs nothing doing");

        let stored = registry
            .get(key)
            .await
            .expect("should read")
            .expect("a row");
        assert_eq!(stored.valid_from, 1_780_000_000);
    }

    /// The whole point of the background task: a host whose key is not registered never reports
    /// ready, however long the registry stays unreachable.
    #[tokio::test(start_paused = true)]
    async fn registration_keeps_retrying_and_publishes_nothing_until_it_lands() {
        use crate::enclave::{EnclaveClient, EnclaveClientError};
        use async_trait::async_trait;
        use deepface_types::{MatchRequest, MatchResponse};
        use std::sync::atomic::{AtomicU32, Ordering};

        /// Never answers, so registration can only keep retrying.
        struct UnreachableEnclave {
            calls: AtomicU32,
        }

        #[async_trait]
        impl EnclaveClient for UnreachableEnclave {
            async fn health(&self) -> Result<(), EnclaveClientError> {
                Ok(())
            }

            async fn encryption_key_attestation(&self) -> Result<Vec<u8>, EnclaveClientError> {
                unreachable!("registration asks only for the signing key")
            }

            async fn signing_key_attestation(&self) -> Result<Vec<u8>, EnclaveClientError> {
                self.calls.fetch_add(1, Ordering::SeqCst);

                Err(EnclaveClientError::Timeout)
            }

            async fn run_match(
                &self,
                _: MatchRequest,
            ) -> Result<MatchResponse, EnclaveClientError> {
                unreachable!("registration runs no matches")
            }
        }

        let enclave = Arc::new(UnreachableEnclave {
            calls: AtomicU32::new(0),
        });
        let (sender, receiver) = watch::channel(None);

        let task = tokio::spawn(register_signing_key(
            enclave.clone(),
            Arc::new(InMemoryKeyRegistry::new()),
            super::verifier(vec![9; 48], false),
            sender,
        ));

        tokio::time::sleep(Duration::from_mins(5)).await;

        assert!(!task.is_finished(), "registration should still be trying");
        assert_eq!(
            *receiver.borrow(),
            None,
            "nothing is published until it lands"
        );
        assert!(
            enclave.calls.load(Ordering::SeqCst) > 1,
            "the enclave should have been asked more than once"
        );

        task.abort();
    }
}

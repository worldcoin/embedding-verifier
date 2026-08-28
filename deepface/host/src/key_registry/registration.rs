//! Putting this boot's `Signing Key` into the registry, and taking it out again.
//!
//! §7.1: the host reads the enclave's signing-key attestation and appends it. Until that lands
//! no verifier can check a statement this enclave signs, so readiness stays red until it does.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use attested_channel::nitro::{
    EnclaveAttestationError, EnclaveAttestationVerifier, PcrMeasurement, VerifiedAttestation,
};
use rand::Rng as _;
use tokio::sync::watch;

use super::{
    InvalidSigningPublicKey, KeyRegistry, KeyStatus, RegistryEntry, RegistryError, SigningPublicKey,
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

/// Registers this boot's signing key, retrying until it lands, then publishes it on `registered`.
///
/// Runs as a background task. Nothing else reports the host ready, so an unreachable registry
/// leaves readiness red and the load balancer sends this host no traffic.
pub async fn register_signing_key(
    enclave_client: Arc<dyn EnclaveClient>,
    registry: Arc<dyn KeyRegistry>,
    verifier: EnclaveAttestationVerifier,
    registered: watch::Sender<Option<SigningPublicKey>>,
) {
    let mut attempt: u32 = 0;
    let mut backoff = INITIAL_BACKOFF;

    loop {
        attempt = attempt.saturating_add(1);

        match register_once(enclave_client.as_ref(), registry.as_ref(), &verifier).await {
            Ok(public_key) => {
                tracing::info!(%public_key, attempt, "registered this boot's signing key");
                // The receiver lives in the app state, which outlives this task.
                let _ = registered.send(Some(public_key));
                return;
            }
            Err(error) => tracing::warn!(
                %error,
                attempt,
                dependency = "key-registry",
                "could not register this boot's signing key; readiness stays red"
            ),
        }

        tokio::time::sleep(jittered(backoff)).await;
        backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
    }
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

    registry.set(&entry).await?;

    Ok(public_key)
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

/// Full jitter, so a fleet restarting together does not retry in lockstep.
fn jittered(backoff: Duration) -> Duration {
    let millis = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX);

    Duration::from_millis(rand::thread_rng().gen_range(0..=millis))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    use attested_channel::nitro::VerifiedAttestation;
    use tokio::sync::watch;

    use super::{
        INITIAL_BACKOFF, MAX_BACKOFF, RegistrationError, entry_from, jittered,
        register_signing_key, retire_signing_key,
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

    #[test]
    fn jitter_never_exceeds_the_backoff_it_is_given() {
        for backoff in [INITIAL_BACKOFF, MAX_BACKOFF] {
            for _ in 0..100 {
                assert!(jittered(backoff) <= backoff);
            }
        }
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

    /// The whole point of the background task: a host whose key is not registered never reports
    /// ready, however long the registry stays unreachable.
    #[tokio::test(start_paused = true)]
    async fn registration_keeps_retrying_and_publishes_nothing_until_it_lands() {
        use crate::enclave::{EnclaveClient, EnclaveClientError};
        use async_trait::async_trait;
        use deepface_types::{MatchRequest, MatchResponse};
        use std::sync::atomic::{AtomicU32, Ordering};

        /// Refuses the attestation until it has been asked `successful_after` times.
        struct FlakyEnclave {
            calls: AtomicU32,
            successful_after: u32,
        }

        #[async_trait]
        impl EnclaveClient for FlakyEnclave {
            async fn health(&self) -> Result<(), EnclaveClientError> {
                Ok(())
            }

            async fn encryption_key_attestation(&self) -> Result<Vec<u8>, EnclaveClientError> {
                unreachable!("registration asks only for the signing key")
            }

            async fn signing_key_attestation(&self) -> Result<Vec<u8>, EnclaveClientError> {
                if self.calls.fetch_add(1, Ordering::SeqCst) < self.successful_after {
                    return Err(EnclaveClientError::Timeout);
                }

                unreachable!("this test never gets as far as verifying a document")
            }

            async fn run_match(
                &self,
                _: MatchRequest,
            ) -> Result<MatchResponse, EnclaveClientError> {
                unreachable!("registration runs no matches")
            }
        }

        let enclave = Arc::new(FlakyEnclave {
            calls: AtomicU32::new(0),
            successful_after: u32::MAX,
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

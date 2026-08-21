//! Keeps the cached attestation documents current, ahead of any request needing them.
//!
//! Refreshing on read would still leave the first request after each interval waiting on the NSM.
//! Refreshing on a timer takes the ioctl off the request path entirely and makes NSM load a
//! constant rather than a function of traffic — 6 calls an hour per key, which doubles as a
//! liveness check on the device.

use std::sync::Arc;
use std::time::Duration;

use enclave_types::EnclaveError;
use rand::Rng as _;
use tokio::task::JoinHandle;

use crate::attested_key::{MAX_SERVED_AGE, REFRESH_INTERVAL};
use crate::state::EnclaveState;

/// Delay before the first retry after a failed refresh.
const BASE_RETRY_DELAY: Duration = Duration::from_secs(5);

/// Ceiling on the delay between retries, so repeated failures keep probing the NSM.
const MAX_RETRY_DELAY: Duration = Duration::from_mins(1);

/// Starts the task that re-attests both boot keys on [`REFRESH_INTERVAL`].
///
/// Detached for the life of the enclave. If it stops, the cached documents age past
/// [`MAX_SERVED_AGE`] and requests fail closed with [`EnclaveError::NotReady`] — the cache never
/// serves a document a client would reject.
pub fn spawn(state: Arc<EnclaveState>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut failures: u32 = 0;

        loop {
            let delay = if failures == 0 {
                REFRESH_INTERVAL
            } else {
                retry_delay(failures)
            };
            tokio::time::sleep(delay).await;

            match refresh(&state).await {
                Ok(()) => {
                    failures = 0;
                    tracing::debug!("refreshed the enclave attestation documents");
                }
                Err(error) => {
                    failures = failures.saturating_add(1);
                    report(error, failures, state.oldest_attestation_age());
                }
            }
        }
    })
}

/// Re-attests both keys off the runtime's workers: `nsm_process_request` is a blocking ioctl.
async fn refresh(state: &Arc<EnclaveState>) -> Result<(), EnclaveError> {
    let state = Arc::clone(state);

    tokio::task::spawn_blocking(move || state.refresh_attestations())
        .await
        .map_err(|error| {
            tracing::error!(%error, "the attestation refresh task panicked");
            EnclaveError::Internal
        })?
}

/// Logs a failed refresh, escalating once the documents stop being servable.
///
/// Below the ceiling this is still degraded-but-serving, so it is a warning. Past it, assignment
/// requests are failing and readiness is down, which is an error.
fn report(error: EnclaveError, failures: u32, age: Duration) {
    if age >= MAX_SERVED_AGE {
        tracing::error!(
            ?error,
            failures,
            age_secs = age.as_secs(),
            dependency = "nsm",
            "attestation documents have aged out; assignment requests are failing"
        );
    } else {
        tracing::warn!(
            ?error,
            failures,
            age_secs = age.as_secs(),
            dependency = "nsm",
            "failed to refresh the enclave attestation documents"
        );
    }
}

/// Delay before the next attempt after `failures` consecutive failures.
///
/// Exponential from [`BASE_RETRY_DELAY`] to [`MAX_RETRY_DELAY`], then jittered down by up to 25% so
/// a fleet that rebooted together does not resynchronise onto one retry tick.
fn retry_delay(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(u32::BITS - 1);
    let backoff = BASE_RETRY_DELAY
        .saturating_mul(1u32 << doublings)
        .min(MAX_RETRY_DELAY);

    jitter(backoff)
}

/// Trims `delay` by a random slice of up to 25% of itself.
///
/// Downward only, so [`MAX_RETRY_DELAY`] stays a true ceiling rather than a midpoint.
fn jitter(delay: Duration) -> Duration {
    let millis = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
    let spread = millis / 4;
    if spread == 0 {
        return delay;
    }

    let trim = rand::thread_rng().gen_range(0..=spread);

    Duration::from_millis(millis.saturating_sub(trim))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{BASE_RETRY_DELAY, MAX_RETRY_DELAY, retry_delay};

    /// Jitter makes the exact value unpredictable, so the bounds are what get pinned.
    fn bounds(nominal: Duration) -> (Duration, Duration) {
        (nominal * 3 / 4, nominal)
    }

    #[test]
    fn the_first_retry_is_near_the_base_delay() {
        let (low, high) = bounds(BASE_RETRY_DELAY);
        let delay = retry_delay(1);

        assert!(delay >= low && delay <= high, "{delay:?}");
    }

    #[test]
    fn retries_back_off() {
        let (low, high) = bounds(BASE_RETRY_DELAY * 4);
        let delay = retry_delay(3);

        assert!(delay >= low && delay <= high, "{delay:?}");
    }

    /// The cap has to hold for every input, including ones that would overflow the shift.
    #[test]
    fn the_delay_is_capped() {
        for failures in [8, 32, 64, u32::MAX] {
            let delay = retry_delay(failures);

            assert!(delay <= MAX_RETRY_DELAY, "{failures} gave {delay:?}");
            assert!(
                delay >= MAX_RETRY_DELAY * 3 / 4,
                "{failures} gave {delay:?}"
            );
        }
    }
}

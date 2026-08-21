//! Keeps the cached attestation documents current, ahead of any request needing them.
//!
//! Refreshing on read would still leave the first request after each interval waiting on the NSM.

use std::sync::Arc;
use std::time::Duration;

use enclave_types::EnclaveError;
use rand::Rng as _;
use tokio::task::JoinHandle;

use crate::attested_key::REFRESH_INTERVAL;
use crate::state::EnclaveState;

/// Delay before the first retry after a failed refresh.
const BASE_RETRY_DELAY: Duration = Duration::from_secs(5);

/// Ceiling on the retry delay.
const MAX_RETRY_DELAY: Duration = Duration::from_mins(1);

/// Starts the task that re-attests both boot keys on [`REFRESH_INTERVAL`].
///
/// Detached for the life of the enclave. If it stops, the documents age out and requests fail
/// closed rather than serving something a client would reject.
pub fn spawn(state: Arc<EnclaveState>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut failures: u32 = 0;

        loop {
            tokio::time::sleep(if failures == 0 {
                REFRESH_INTERVAL
            } else {
                retry_delay(failures)
            })
            .await;

            match refresh(&state).await {
                Ok(()) => {
                    failures = 0;
                    tracing::debug!("refreshed the attestation documents");
                }
                Err(error) => {
                    failures = failures.saturating_add(1);
                    if state.attestations_are_servable() {
                        tracing::warn!(?error, failures, dependency = "nsm", "refresh failed");
                    } else {
                        tracing::error!(
                            ?error,
                            failures,
                            dependency = "nsm",
                            "documents have aged out; requests are failing"
                        );
                    }
                }
            }
        }
    })
}

/// Re-attests off the runtime's workers: `nsm_process_request` is a blocking ioctl.
async fn refresh(state: &Arc<EnclaveState>) -> Result<(), EnclaveError> {
    let state = Arc::clone(state);

    tokio::task::spawn_blocking(move || state.refresh_attestations())
        .await
        .map_err(|error| {
            tracing::error!(%error, "the attestation refresh task panicked");
            EnclaveError::Internal
        })?
}

/// Exponential from [`BASE_RETRY_DELAY`] to [`MAX_RETRY_DELAY`], trimmed by up to 25% so a fleet
/// that rebooted together does not resynchronise. Downward, so the cap stays a real one.
fn retry_delay(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(u32::BITS - 1);
    let backoff = BASE_RETRY_DELAY
        .saturating_mul(1u32 << doublings)
        .min(MAX_RETRY_DELAY);

    let millis = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX);
    let trim = rand::thread_rng().gen_range(0..=millis / 4);

    Duration::from_millis(millis - trim)
}

#[cfg(test)]
mod tests {
    use super::{BASE_RETRY_DELAY, MAX_RETRY_DELAY, retry_delay};

    /// Jitter makes the value unpredictable, so only the bounds are pinned. Large inputs are
    /// included because the backoff shifts by `failures`.
    #[test]
    fn retries_back_off_within_the_cap() {
        assert!(retry_delay(1) >= BASE_RETRY_DELAY * 3 / 4);

        for failures in [1, 3, 8, u32::MAX] {
            assert!(retry_delay(failures) <= MAX_RETRY_DELAY, "{failures}");
        }
    }
}

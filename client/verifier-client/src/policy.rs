//! Builds a verification policy from the environment.
//!
//! Unlike `worldcoin/bedrock`, expected measurements cannot be compile-time constants: our
//! image is built per branch, so PCR0 is only known once `scripts/build-eif.sh` publishes it.

use std::time::Duration;

use crate::nitro::{EnclaveAttestationVerifier, PcrMeasurement};

/// PCR indices the image measurement is spread across: image, kernel, application, signing
/// certificate. Every index that is configured must match.
pub const PINNABLE_PCR_INDICES: [u32; 4] = [0, 1, 2, 8];

/// Default freshness bound, matching the few-hour lifetime of a Nitro certificate.
// `Duration::from_hours` is unstable on 1.97.
#[allow(clippy::duration_suboptimal_units)]
const DEFAULT_MAX_AGE: Duration = Duration::from_secs(60 * 60);

/// Failures while reading the verification policy.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// No expected measurements were configured.
    #[error(
        "no expected PCRs configured: set at least EXPECTED_PCR0 to the value published by \
         scripts/build-eif.sh. Without it, verification proves a document came from some \
         enclave, not from ours"
    )]
    NoExpectedPcrs,

    /// A configured PCR value was not hex.
    #[error("EXPECTED_PCR{index} must be hex: {reason}")]
    MalformedPcr {
        /// The PCR index whose value could not be read.
        index: u32,
        /// Why it could not be read.
        reason: String,
    },

    /// `MAX_ATTESTATION_AGE_SECS` was not a usable number of seconds.
    #[error("MAX_ATTESTATION_AGE_SECS must be a whole number of seconds: {0}")]
    MalformedMaxAge(String),
}

/// Builds a verifier from `EXPECTED_PCR*`, `ALLOW_DEBUG_MEASUREMENTS` and
/// `MAX_ATTESTATION_AGE_SECS`.
///
/// Fails when nothing is pinned: an empty policy would accept any genuine Nitro enclave,
/// including somebody else's.
///
/// # Errors
///
/// Returns [`PolicyError`] if no PCRs are configured or a value cannot be parsed.
pub fn verifier_from_env() -> Result<EnclaveAttestationVerifier, PolicyError> {
    let expected_pcrs = expected_pcrs_from_env()?;
    if expected_pcrs.is_empty() {
        return Err(PolicyError::NoExpectedPcrs);
    }

    let max_age = match std::env::var("MAX_ATTESTATION_AGE_SECS") {
        Ok(value) => Duration::from_secs(
            value
                .trim()
                .parse()
                .map_err(|error| PolicyError::MalformedMaxAge(format!("{error}")))?,
        ),
        Err(_) => DEFAULT_MAX_AGE,
    };

    let max_age_millis = u64::try_from(max_age.as_millis())
        .map_err(|_| PolicyError::MalformedMaxAge("value is too large".to_string()))?;

    let verifier = EnclaveAttestationVerifier::new(vec![expected_pcrs], max_age_millis);

    if allows_debug_measurements() {
        tracing::warn!(
            "accepting zeroed measurements: a debug-mode enclave's memory is readable from \
             the parent instance"
        );
        return Ok(verifier.allowing_debug_measurements());
    }

    Ok(verifier)
}

/// Whether the caller opted in to debug-mode enclaves.
#[must_use]
pub fn allows_debug_measurements() -> bool {
    std::env::var("ALLOW_DEBUG_MEASUREMENTS").is_ok_and(|value| value.trim() == "true")
}

fn expected_pcrs_from_env() -> Result<Vec<PcrMeasurement>, PolicyError> {
    PINNABLE_PCR_INDICES
        .into_iter()
        .filter_map(|index| {
            let value = std::env::var(format!("EXPECTED_PCR{index}")).ok()?;
            Some((index, value))
        })
        .map(|(index, value)| {
            let bytes = hex::decode(value.trim()).map_err(|error| PolicyError::MalformedPcr {
                index,
                reason: format!("{error}"),
            })?;
            Ok(PcrMeasurement::new(index, bytes))
        })
        .collect()
}

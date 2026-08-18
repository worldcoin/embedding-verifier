//! Fetches an enclave assignment from a host and verifies its attestation document.
//!
//! ```bash
//! VERIFIER_BASE_URL=http://localhost:8000 \
//! EXPECTED_PCR0=<hex> \
//!   cargo run --bin verifier-client
//! ```
//!
//! Exits non-zero if verification fails, so it can be used as a deployment smoke test.

use std::time::{Duration, SystemTime};

use anyhow::{Context as _, Result, anyhow, bail};
use verifier_client::http::Client;
use verifier_client::nitro::{EnclaveAttestationVerifier, PcrMeasurement};

/// PCR indices the enclave image measurement is spread across.
///
/// PCR0 is the image itself, PCR1 the kernel and bootstrap, PCR2 the application, PCR8 the
/// signing certificate. Any that are configured are required to match.
const PINNABLE_PCR_INDICES: [u32; 4] = [0, 1, 2, 8];

/// Default freshness bound, matching the few-hour lifetime of a Nitro certificate.
const DEFAULT_MAX_AGE: Duration = Duration::from_secs(60 * 60);

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let base_url =
        std::env::var("VERIFIER_BASE_URL").unwrap_or_else(|_| "http://localhost:8000".to_string());

    let expected_pcrs = expected_pcrs()?;
    let allow_debug = std::env::var("ALLOW_DEBUG_MEASUREMENTS").is_ok_and(|value| value == "true");

    if expected_pcrs.is_empty() {
        bail!(
            "no expected PCRs configured; set at least EXPECTED_PCR0 to the value published by \
             scripts/build-eif.sh, otherwise there is nothing to verify the enclave against"
        );
    }

    let max_age = match std::env::var("MAX_ATTESTATION_AGE_SECS") {
        Ok(value) => Duration::from_secs(
            value
                .parse()
                .context("MAX_ATTESTATION_AGE_SECS must be a whole number of seconds")?,
        ),
        Err(_) => DEFAULT_MAX_AGE,
    };

    let mut verifier = EnclaveAttestationVerifier::new(
        vec![expected_pcrs],
        u64::try_from(max_age.as_millis()).context("MAX_ATTESTATION_AGE_SECS is too large")?,
    );
    if allow_debug {
        tracing::warn!(
            "accepting zeroed measurements: a debug-mode enclave offers no confidentiality, \
             its memory is readable from the parent instance"
        );
        verifier = verifier.allowing_debug_measurements();
    }

    let client = Client::new(&base_url, verifier).context("failed to build the client")?;

    let verified = client
        .request_assignment(SystemTime::now())
        .await
        .with_context(|| format!("enclave assignment from {base_url} did not verify"))?;

    println!("attestation verified against the pinned AWS Nitro root");
    println!("  enclave id     : {}", verified.module_id);
    println!(
        "  encryption key : {}",
        hex::encode(&verified.enclave_public_key)
    );
    println!(
        "  attested at    : {} ms since epoch",
        verified.timestamp_millis
    );
    for (index, value) in &verified.pcrs {
        // Skip the unused registers, which are all zero and only add noise.
        if value.iter().any(|byte| *byte != 0) {
            println!("  PCR{index:<11}: {}", hex::encode(value));
        }
    }

    Ok(())
}

/// Reads the expected PCR values from the environment.
fn expected_pcrs() -> Result<Vec<PcrMeasurement>> {
    PINNABLE_PCR_INDICES
        .into_iter()
        .filter_map(|index| {
            let value = std::env::var(format!("EXPECTED_PCR{index}")).ok()?;
            Some((index, value))
        })
        .map(|(index, value)| {
            // The workspace pins hex without std, so FromHexError is not an std::error::Error.
            let bytes = hex::decode(value.trim())
                .map_err(|error| anyhow!("EXPECTED_PCR{index} must be hex: {error}"))?;
            Ok(PcrMeasurement::new(index, bytes))
        })
        .collect()
}

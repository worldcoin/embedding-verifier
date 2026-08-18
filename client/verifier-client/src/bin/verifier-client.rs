//! Fetches an enclave assignment from a host and verifies its attestation document.
//!
//! Exits non-zero if verification fails, so it works as a deployment smoke test.
//!
//! ```bash
//! VERIFIER_BASE_URL=http://localhost:8000 \
//! EXPECTED_PCR0=<hex published by scripts/build-eif.sh> \
//!   cargo run --bin verifier-client
//! ```

use std::time::SystemTime;

use anyhow::{Context as _, Result};
use verifier_client::http::Client;
use verifier_client::policy::verifier_from_env;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let base_url =
        std::env::var("VERIFIER_BASE_URL").unwrap_or_else(|_| "http://localhost:8000".to_string());

    let verifier = verifier_from_env().context("failed to read the verification policy")?;
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
        // Skip unused registers, which are all zero.
        if value.iter().any(|byte| *byte != 0) {
            println!("  PCR{index:<11}: {}", hex::encode(value));
        }
    }

    Ok(())
}

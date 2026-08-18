use std::sync::Arc;

use anyhow::{Context, anyhow};
use pontifex::SecureModule;
use secure_enclave::{
    attestation::{self, NsmAttestor},
    face_engine::FaceEngine,
    pontifex_server, rng,
    state::EnclaveState,
};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

const PONTIFEX_PORT: u32 = 1000;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Every step below is a hard gate. An enclave that cannot prove its own identity, or
    // whose entropy is not the NSM's, must not serve traffic at all — surfacing that as
    // per-request failures once clients arrive would be strictly worse.
    rng::verify_nsm_hwrng_current().context("Nitro hardware RNG is not configured")?;
    attestation::connect()
        .await
        .context("Nitro Secure Module is unavailable")?;

    let face_engine = Arc::new(FaceEngine::default());
    info!("initialized Face Engine");
    let state = Arc::new(
        EnclaveState::generate(Arc::new(NsmAttestor), face_engine)
            .context("failed to generate boot-scoped enclave keys")?,
    );

    let attestation = state
        .attest_encryption_key()
        .map_err(|error| anyhow!("failed to attest the encryption key at boot: {error:?}"))?;
    let document = SecureModule::parse_raw_attestation_doc(&attestation)
        .map_err(|error| anyhow!("failed to parse the boot attestation document: {error:?}"))?;
    attestation::log_boot_measurements(&document);

    info!(port = PONTIFEX_PORT, "starting enclave Pontifex server");

    pontifex_server::start(state, PONTIFEX_PORT)
        .await
        .map_err(|error| {
            error!(%error, "enclave Pontifex server stopped");
            error
        })
}

use std::sync::Arc;

use anyhow::{Context, anyhow};
use flamingo_verifier_enclave::{
    attestation::{self, NsmAttestor},
    face_engine::FaceEngine,
    rng, server,
    state::EnclaveState,
};
use pontifex::SecureModule;
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
    // Attests both boot keys, so a broken NSM stops the boot and both caches start populated.
    let mut state = EnclaveState::generate(Arc::new(NsmAttestor), face_engine)
        .map_err(|error| anyhow!("failed to generate and attest the boot keys: {error:?}"))?;
    let (encryption_refresh, signing_refresh) = state.start_attestation_refresh();
    let state = Arc::new(state);

    let document = SecureModule::global()
        .attest(None::<Vec<u8>>, None::<Vec<u8>>, None::<Vec<u8>>)
        .context("failed to read boot measurements")?;
    attestation::log_boot_measurements(&document);

    info!(port = PONTIFEX_PORT, "starting enclave Pontifex server");

    tokio::select! {
        result = server::start(state, PONTIFEX_PORT) => {
            result.map_err(|error| {
                error!(%error, "enclave Pontifex server stopped");
                error
            })
        }
        result = encryption_refresh => {
            Err(anyhow!(
                "encryption key attestation refresh stopped: {result:?}"
            ))
        }
        result = signing_refresh => {
            Err(anyhow!(
                "signing key attestation refresh stopped: {result:?}"
            ))
        }
    }
}

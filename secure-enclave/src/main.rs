use std::sync::Arc;

use anyhow::Context;
use secure_enclave::{face_engine::FaceEngine, pontifex_server, rng, state::EnclaveState};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

const PONTIFEX_PORT: u32 = 1000;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    rng::verify_nsm_hwrng_current().context("Nitro hardware RNG is not configured")?;
    let face_engine = Arc::new(FaceEngine::default());
    info!("initialized Face Engine");
    let state = Arc::new(EnclaveState::generate(face_engine));

    info!(port = PONTIFEX_PORT, "starting enclave Pontifex server");

    pontifex_server::start(state, PONTIFEX_PORT)
        .await
        .map_err(|error| {
            error!(%error, "enclave Pontifex server stopped");
            error
        })
}

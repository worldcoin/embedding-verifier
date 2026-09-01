use std::sync::Arc;

use deepface_host::{
    AppState, Environment, challenge_store::InMemoryChallengeStore, enclave::PontifexEnclaveClient,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Keep the guard alive until the server stops so buffered spans are flushed.
    let _telemetry = telemetry_batteries::init()
        .map_err(|error| anyhow::anyhow!("failed to initialize telemetry: {error:?}"))?;

    let environment = Environment::from_env();
    tracing::info!(?environment, "Starting API");

    let enclave_client = Arc::new(PontifexEnclaveClient::new(
        environment.enclave_cid(),
        environment.enclave_port(),
    ));
    // In-memory pending the shared (S3) store: single-host only, see `challenge_store`.
    let challenge_store = Arc::new(InMemoryChallengeStore::new());
    let state = AppState::new(environment, enclave_client, challenge_store);

    deepface_host::server::start(state).await
}

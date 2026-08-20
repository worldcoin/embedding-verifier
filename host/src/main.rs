use std::sync::Arc;

use host::{
    AppState, Environment, challenge_fetch::ChallengeFetcher, enclave::PontifexEnclaveClient,
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let environment = Environment::from_env();
    tracing::info!(?environment, "Starting API");

    let enclave_client = Arc::new(PontifexEnclaveClient::new(
        environment.enclave_cid(),
        environment.enclave_port(),
    ));
    // A broken allowlist fails the boot rather than the first request.
    let challenge_source = Arc::new(ChallengeFetcher::new(
        &environment.challenge_image_allowlist(),
    )?);
    let state = AppState::new(environment, enclave_client, challenge_source);

    host::server::start(state).await
}

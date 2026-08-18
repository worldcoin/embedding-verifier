use std::sync::Arc;

use anyhow::Context;
use api::{
    config::Config,
    enclave::PontifexEnclaveClient,
    readiness::{self, Readiness},
    telemetry::Metrics,
    types::AppState,
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = Config::from_env().context("failed to resolve configuration")?;
    tracing::info!(
        environment = ?config.environment,
        port = config.port,
        enclave_cid = config.enclave_cid,
        "starting API"
    );

    let metrics = Arc::new(Metrics::new(&config).context("failed to initialise metrics")?);
    let enclave_client = Arc::new(PontifexEnclaveClient::new(
        config.enclave_cid,
        config.enclave_port,
    ));
    let readiness_state = Arc::new(Readiness::new());

    // Readiness is maintained off the request path; the instance stays unready until the
    // first probe succeeds.
    readiness::spawn_enclave_prober(
        enclave_client.clone(),
        Arc::clone(&readiness_state),
        Arc::clone(&metrics),
    );

    let state = AppState::new(Arc::new(config), enclave_client, readiness_state, metrics);

    api::server::start(state).await
}

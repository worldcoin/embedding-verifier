use std::sync::Arc;

use deepface_host::key_registry::{DynamoKeyRegistry, KeyRegistry, register_signing_key, verifier};
use deepface_host::{
    AppState, Environment, challenge_fetcher::ChallengeFetcher, enclave::PontifexEnclaveClient,
};
use tokio::sync::watch;
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
    let challenge_source = Arc::new(ChallengeFetcher::new()?);

    let key_registry: Arc<dyn KeyRegistry> =
        Arc::new(DynamoKeyRegistry::new(environment.key_registry_table()).await);

    // Registration runs in the background and readiness waits on it, so a registry outage leaves
    // this host out of the load balancer rather than signing statements nobody can verify.
    let (registered, watch_registered) = watch::channel(None);
    tokio::spawn(register_signing_key(
        enclave_client.clone(),
        Arc::clone(&key_registry),
        verifier(
            environment.enclave_pcr0(),
            environment.allow_debug_measurements(),
        ),
        registered,
    ));

    let state = AppState::new(
        environment,
        enclave_client,
        challenge_source,
        key_registry,
        watch_registered,
    );

    deepface_host::server::start(state).await
}

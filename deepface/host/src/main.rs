use std::sync::Arc;

use deepface_host::key_registry::{
    DynamoKeyRegistry, InMemoryKeyRegistry, KeyRegistry, register_signing_key, verifier,
};
use deepface_host::{
    AppState, Environment, KeyRegistryStore, challenge_fetcher::ChallengeFetcher,
    enclave::PontifexEnclaveClient,
};
use tokio::sync::watch;

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
    // A missing or broken base URL fails the boot, not the first request.
    let challenge_source = Arc::new(ChallengeFetcher::new(
        &environment.challenge_image_base_url(),
    )?);

    // KEY_REGISTRY names the store, so a missing table is a startup panic rather than a host that
    // looks healthy while signing against a registry that dies with it.
    let key_registry: Arc<dyn KeyRegistry> = match environment.key_registry() {
        KeyRegistryStore::DynamoDb => {
            Arc::new(DynamoKeyRegistry::new(environment.key_registry_table()).await)
        }
        KeyRegistryStore::InMemory => {
            tracing::warn!("KEY_REGISTRY=in-memory; the registry dies with this process");
            Arc::new(InMemoryKeyRegistry::new())
        }
    };

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

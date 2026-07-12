use tracing_subscriber::EnvFilter;

use api::types::Environment;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let environment = Environment::from_env();
    tracing::info!(?environment, "Starting API");

    api::server::start(environment).await
}

use secure_enclave::pontifex_server;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

const PONTIFEX_PORT: u32 = 1000;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    info!(port = PONTIFEX_PORT, "starting enclave Pontifex server");

    pontifex_server::start(PONTIFEX_PORT)
        .await
        .map_err(|error| {
            error!(%error, "enclave Pontifex server stopped");
            error
        })
}

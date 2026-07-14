use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    info!("Secure enclave started");
    tokio::signal::ctrl_c().await?;
    info!("Secure enclave shutting down");

    Ok(())
}

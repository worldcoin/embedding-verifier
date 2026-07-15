//! Pontifex server setup and operation routing.

use anyhow::Context;
use enclave_types::HealthRequest;
use pontifex::Router;

mod health;

/// Starts the enclave's Pontifex server on the provided vsock port.
///
/// # Errors
///
/// Returns an error when Pontifex cannot listen for or serve requests.
pub async fn start(port: u32) -> anyhow::Result<()> {
    router()
        .serve(port)
        .await
        .context("failed to serve Pontifex")
}

fn router() -> Router {
    Router::new().route::<HealthRequest, _, _>(health::handler)
}

#[cfg(test)]
mod tests {
    use super::router;

    #[test]
    fn router_registers_health_operation() {
        let _router = router();
    }
}

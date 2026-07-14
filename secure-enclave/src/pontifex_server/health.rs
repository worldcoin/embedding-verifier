use enclave_types::{EnclaveError, HealthRequest};

pub async fn handler((): (), _: HealthRequest) -> Result<(), EnclaveError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::handler;
    use enclave_types::HealthRequest;

    #[tokio::test]
    async fn health_succeeds_when_server_is_running() {
        assert_eq!(handler((), HealthRequest).await, Ok(()));
    }
}

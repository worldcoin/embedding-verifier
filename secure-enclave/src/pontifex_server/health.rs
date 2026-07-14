use enclave_types::{EnclaveError, HealthRequest};

pub async fn handler((): (), _: HealthRequest) -> Result<(), EnclaveError> {
    Ok(())
}

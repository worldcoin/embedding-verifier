use std::sync::Arc;

use deepface_enclave_types::{EnclaveError, HealthRequest};

use crate::state::EnclaveState;

pub async fn handler(_: Arc<EnclaveState>, _: HealthRequest) -> Result<(), EnclaveError> {
    Ok(())
}

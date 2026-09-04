use std::sync::Arc;

use flamingo_verifier_enclave_types::{EnclaveError, HealthRequest};

use crate::state::EnclaveState;

pub async fn handler(_: Arc<EnclaveState>, _: HealthRequest) -> Result<(), EnclaveError> {
    Ok(())
}

use std::sync::Arc;

use flamingo_verifier_enclave_types as enclave_types;
use flamingo_verifier_enclave_types::HealthRequest;

use crate::state::EnclaveState;

pub async fn handler(_: Arc<EnclaveState>, _: HealthRequest) -> Result<(), enclave_types::Error> {
    Ok(())
}

use std::sync::Arc;

use enclave_types::{EnclaveError, GetTransitKeyRequest, GetTransitKeyResponse};
use pontifex::SecureModule;

use crate::state::EnclaveState;

pub async fn handler(
    state: Arc<EnclaveState>,
    _: GetTransitKeyRequest,
) -> Result<GetTransitKeyResponse, EnclaveError> {
    let secure_module =
        SecureModule::try_global().ok_or(EnclaveError::SecureModuleNotInitialized)?;
    let public_key = state.transit_public_key();

    let attestation = secure_module
        .raw_attest(None::<Vec<u8>>, None::<Vec<u8>>, Some(public_key.to_vec()))
        .map_err(|error| {
            tracing::error!(?error, "failed to attest transit public key");
            EnclaveError::AttestationFailed
        })?;

    Ok(GetTransitKeyResponse { attestation })
}

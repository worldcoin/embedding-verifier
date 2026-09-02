use std::sync::Arc;

use deepface_enclave_types::{EnclaveError, GetSigningKeyRequest, KeyAttestation};

use crate::state::EnclaveState;

/// Returns the cached signing-key attestation document.
pub async fn handler(
    state: Arc<EnclaveState>,
    _: GetSigningKeyRequest,
) -> Result<KeyAttestation, EnclaveError> {
    Ok(KeyAttestation {
        document: state.signing_key_attestation().await,
    })
}

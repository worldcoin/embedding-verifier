use std::sync::Arc;

use flamingo_verifier_enclave_types::{EnclaveError, GetEncryptionKeyRequest, KeyAttestation};

use crate::state::EnclaveState;

/// Returns the cached encryption-key attestation document.
pub async fn handler(
    state: Arc<EnclaveState>,
    _: GetEncryptionKeyRequest,
) -> Result<KeyAttestation, EnclaveError> {
    Ok(KeyAttestation {
        document: state.encryption_key_attestation().await,
    })
}

use std::sync::Arc;

use enclave_types::{EnclaveError, GetEncryptionKeyRequest, KeyAttestation};

use crate::state::EnclaveState;

/// Returns the encryption key's attestation, from cache unless it has expired.
pub async fn handler(
    state: Arc<EnclaveState>,
    _: GetEncryptionKeyRequest,
) -> Result<KeyAttestation, EnclaveError> {
    Ok(KeyAttestation {
        document: state.encryption_key_attestation().await?,
    })
}

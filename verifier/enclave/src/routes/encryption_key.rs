use std::sync::Arc;

use flamingo_verifier_enclave_types as enclave_types;
use flamingo_verifier_enclave_types::{GetEncryptionKeyRequest, KeyAttestation};

use crate::state::EnclaveState;

/// Returns the cached encryption-key attestation document.
pub async fn handler(
    state: Arc<EnclaveState>,
    _: GetEncryptionKeyRequest,
) -> Result<KeyAttestation, enclave_types::Error> {
    Ok(KeyAttestation {
        document: state.encryption_key_attestation().await,
    })
}

use std::sync::Arc;

use enclave_types::{EnclaveError, GetSigningKeyRequest, KeyAttestation};

use crate::state::EnclaveState;

/// Returns the signing key's attestation, from cache unless it has expired.
pub async fn handler(
    state: Arc<EnclaveState>,
    _: GetSigningKeyRequest,
) -> Result<KeyAttestation, EnclaveError> {
    Ok(KeyAttestation {
        document: state.signing_key_attestation().await?,
    })
}

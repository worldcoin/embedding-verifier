use std::sync::Arc;

use enclave_types::{EnclaveError, GetEnclaveKeysRequest, GetEnclaveKeysResponse};

use crate::state::EnclaveState;

/// Returns one attestation document per public key.
pub async fn handler(
    state: Arc<EnclaveState>,
    _: GetEnclaveKeysRequest,
) -> Result<GetEnclaveKeysResponse, EnclaveError> {
    let encryption_key_attestation = state.attest_encryption_key()?;
    let signing_key_attestation = state.attest_signing_key()?;

    Ok(GetEnclaveKeysResponse {
        encryption_key_attestation,
        signing_key_attestation,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use enclave_types::{EnclaveError, GetEnclaveKeysRequest};

    use super::handler;
    use crate::test_support::{FailingAttestor, state_with};

    #[tokio::test]
    async fn handler_propagates_attestation_failures() {
        let state = state_with(Arc::new(FailingAttestor));

        let result = handler(state, GetEnclaveKeysRequest).await;

        assert_eq!(result, Err(EnclaveError::AttestationFailed));
    }
}

use std::sync::Arc;

use enclave_types::{EnclaveError, GetEnclaveKeysRequest, GetEnclaveKeysResponse};

use crate::state::EnclaveState;

/// Returns one attestation document per public key, both from cache.
pub async fn handler(
    state: Arc<EnclaveState>,
    _: GetEnclaveKeysRequest,
) -> Result<GetEnclaveKeysResponse, EnclaveError> {
    Ok(GetEnclaveKeysResponse {
        encryption_key_attestation: state.encryption_key_attestation()?,
        signing_key_attestation: state.signing_key_attestation()?,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use enclave_types::{EnclaveError, GetEnclaveKeysRequest};

    use super::handler;
    use crate::test_support::{EchoAttestor, stale_state_with};

    /// Withheld rather than served stale, so the failure lands here instead of on the client.
    #[tokio::test]
    async fn handler_reports_not_ready_once_the_cache_has_aged_out() {
        let state = stale_state_with(Arc::new(EchoAttestor));

        let result = handler(state, GetEnclaveKeysRequest).await;

        assert_eq!(result, Err(EnclaveError::NotReady));
    }
}

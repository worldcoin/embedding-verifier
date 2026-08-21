use std::sync::Arc;

use enclave_types::{EnclaveError, GetEnclaveKeysRequest, GetEnclaveKeysResponse};

use crate::state::EnclaveState;

/// Returns one attestation document per public key.
///
/// Both come from the enclave's cache, refreshed ahead of use, so no NSM call sits on this path.
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
    use crate::test_support::{EchoAttestor, stale_state_with, state_with};

    #[tokio::test]
    async fn handler_serves_both_documents_from_the_cache() {
        let state = state_with(Arc::new(EchoAttestor));
        let expected = state
            .encryption_key_attestation()
            .expect("a fresh document should be servable");

        let response = handler(Arc::clone(&state), GetEnclaveKeysRequest)
            .await
            .expect("the handler should answer");

        assert_eq!(response.encryption_key_attestation, expected);
        assert_ne!(
            response.signing_key_attestation, response.encryption_key_attestation,
            "each key must be attested in its own document"
        );
    }

    /// A document past the ceiling is withheld rather than served stale, so the failure lands here
    /// as an enclave error instead of on the client as a verification failure.
    #[tokio::test]
    async fn handler_reports_not_ready_once_the_cache_has_aged_out() {
        let state = stale_state_with(Arc::new(EchoAttestor));

        let result = handler(state, GetEnclaveKeysRequest).await;

        assert_eq!(result, Err(EnclaveError::NotReady));
    }
}

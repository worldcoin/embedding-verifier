use std::sync::Arc;

use enclave_types::{EnclaveError, GetSigningKeyRequest, KeyAttestation};

use crate::state::EnclaveState;

/// Returns the signing key's attestation, from cache.
pub async fn handler(
    state: Arc<EnclaveState>,
    _: GetSigningKeyRequest,
) -> Result<KeyAttestation, EnclaveError> {
    Ok(KeyAttestation {
        document: state.signing_key_attestation()?,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use enclave_types::{EnclaveError, GetSigningKeyRequest};

    use super::handler;
    use crate::test_support::{EchoAttestor, stale_state_with};

    /// Withheld rather than served stale, so the failure lands here instead of on the client.
    #[tokio::test]
    async fn reports_not_ready_once_the_cache_has_aged_out() {
        let state = stale_state_with(Arc::new(EchoAttestor));

        assert_eq!(
            handler(state, GetSigningKeyRequest).await,
            Err(EnclaveError::NotReady)
        );
    }
}

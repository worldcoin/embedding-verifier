use std::sync::Arc;

use enclave_types::{EnclaveError, GetEncryptionKeyRequest, GetSigningKeyRequest, KeyAttestation};

use crate::state::EnclaveState;

/// Returns the encryption key's attestation, from cache.
pub async fn encryption_key(
    state: Arc<EnclaveState>,
    _: GetEncryptionKeyRequest,
) -> Result<KeyAttestation, EnclaveError> {
    Ok(KeyAttestation {
        document: state.encryption_key_attestation()?,
    })
}

/// Returns the signing key's attestation, from cache.
pub async fn signing_key(
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

    use enclave_types::{EnclaveError, GetEncryptionKeyRequest, GetSigningKeyRequest};

    use super::{encryption_key, signing_key};
    use crate::test_support::{EchoAttestor, stale_state_with, state_with};

    #[tokio::test]
    async fn each_key_is_served_in_its_own_document() {
        let state = state_with(Arc::new(EchoAttestor));

        let encryption = encryption_key(Arc::clone(&state), GetEncryptionKeyRequest)
            .await
            .expect("should answer");
        let signing = signing_key(state, GetSigningKeyRequest)
            .await
            .expect("should answer");

        assert_ne!(encryption.document, signing.document);
    }

    /// Withheld rather than served stale, so the failure lands here instead of on the client.
    #[tokio::test]
    async fn both_report_not_ready_once_the_cache_has_aged_out() {
        let state = stale_state_with(Arc::new(EchoAttestor));

        assert_eq!(
            encryption_key(Arc::clone(&state), GetEncryptionKeyRequest).await,
            Err(EnclaveError::NotReady)
        );
        assert_eq!(
            signing_key(state, GetSigningKeyRequest).await,
            Err(EnclaveError::NotReady)
        );
    }
}

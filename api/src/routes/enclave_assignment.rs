use axum::{Json, extract::State, http::StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use enclave_types::EnclaveError;
use serde::Serialize;

use crate::enclave::EnclaveClientError;
use crate::types::AppState;

/// The enclave assigned to a client, as an attestation document.
///
/// The document already carries the enclave's identity and expiry, and the client verifies it
/// before trusting either, so the host relays opaque bytes and adds no fields of its own.
#[derive(Debug, Serialize)]
pub struct EnclaveAssignmentResponse {
    attestation: String,
}

/// Assigns this host's enclave by returning its encryption-key attestation.
pub async fn handler(
    State(state): State<AppState>,
) -> Result<Json<EnclaveAssignmentResponse>, StatusCode> {
    // TODO: Cache the attestation document, invalidating on enclave reconnect, and bound the
    // entry's lifetime by the document certificate's validity. Until then every request costs
    // an NSM attestation, so this route must not carry production traffic uncapped.
    let response = state
        .enclave_client()
        .get_enclave_keys()
        .await
        .map_err(|error| {
            let status = status_for(&error);
            tracing::error!(
                ?error,
                %status,
                dependency = "secure-enclave",
                failure_class = error.failure_class(),
                "enclave assignment failed"
            );
            status
        })?;

    // The signing-key attestation belongs to the Key Registry, not to an assignment.
    Ok(Json(EnclaveAssignmentResponse {
        attestation: STANDARD.encode(response.encryption_key_attestation),
    }))
}

/// Maps an enclave-client failure to an HTTP status.
const fn status_for(error: &EnclaveClientError) -> StatusCode {
    match error {
        EnclaveClientError::Timeout => StatusCode::GATEWAY_TIMEOUT,
        EnclaveClientError::Transport(_) => StatusCode::SERVICE_UNAVAILABLE,
        EnclaveClientError::Operation(operation) => match operation {
            EnclaveError::NotReady
            | EnclaveError::SecureModuleNotInitialized
            | EnclaveError::AttestationFailed => StatusCode::SERVICE_UNAVAILABLE,
            // Match-path errors cannot arise from an attestation request. Reaching one means
            // the enclave answered a request it was not asked, so surface a host bug rather
            // than retryable unavailability.
            EnclaveError::DecryptFailed
            | EnclaveError::MalformedMatchPayload
            | EnclaveError::InvalidHashesJson
            | EnclaveError::ThumbnailHashMismatch
            | EnclaveError::MatchBelowThreshold
            | EnclaveError::InvalidImage
            | EnclaveError::EmbeddingGenerationFailed
            | EnclaveError::EmbeddingComparisonFailed => StatusCode::INTERNAL_SERVER_ERROR,
        },
    }
}

#[cfg(test)]
mod tests {
    use axum::{extract::State, http::StatusCode};
    use enclave_types::{EnclaveError, GetEnclaveKeysResponse};

    use super::{handler, status_for};
    use crate::enclave::EnclaveClientError;
    use crate::test_support::{StubEnclaveClient, state_with};

    #[tokio::test]
    async fn returns_the_encryption_key_attestation_and_nothing_else() {
        let state = state_with(StubEnclaveClient {
            keys: Some(Ok(GetEnclaveKeysResponse {
                encryption_key_attestation: vec![1, 2, 3],
                signing_key_attestation: vec![4, 5, 6],
            })),
            ..StubEnclaveClient::default()
        });

        let response = handler(State(state))
            .await
            .expect("a reachable enclave should yield an assignment")
            .0;

        assert_eq!(response.attestation, "AQID");

        let json = serde_json::to_value(&response).expect("response should serialize");
        assert_eq!(json.as_object().map(serde_json::Map::len), Some(1));
    }

    #[tokio::test]
    async fn maps_enclave_failure_to_its_status() {
        let state = state_with(StubEnclaveClient {
            keys: Some(Err(EnclaveClientError::Timeout)),
            ..StubEnclaveClient::default()
        });

        let status = handler(State(state))
            .await
            .expect_err("a timed-out enclave should not yield an assignment");

        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    }

    #[test]
    fn status_mapping_is_exhaustive_and_classified() {
        assert_eq!(
            status_for(&EnclaveClientError::Timeout),
            StatusCode::GATEWAY_TIMEOUT
        );
        assert_eq!(
            status_for(&EnclaveClientError::Transport("boom".to_string())),
            StatusCode::SERVICE_UNAVAILABLE
        );

        for operation in [
            EnclaveError::NotReady,
            EnclaveError::SecureModuleNotInitialized,
            EnclaveError::AttestationFailed,
        ] {
            assert_eq!(
                status_for(&EnclaveClientError::Operation(operation)),
                StatusCode::SERVICE_UNAVAILABLE,
                "{operation:?} should read as retryable unavailability"
            );
        }

        assert_eq!(
            status_for(&EnclaveClientError::Operation(EnclaveError::DecryptFailed)),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}

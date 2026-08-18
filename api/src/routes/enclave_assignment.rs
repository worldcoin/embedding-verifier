use axum::{Json, extract::State, http::StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use enclave_types::EnclaveError;
use serde::Serialize;

use crate::enclave::EnclaveClientError;
use crate::types::AppState;

/// The enclave assigned to a client, as an attestation document.
///
/// The document is the whole response on purpose. It already carries the enclave's identity
/// (`module_id`) and its own expiry (the leaf certificate's `notAfter`), and the client must
/// verify it before trusting either. Echoing those as unsigned JSON fields would restate
/// signed data and create a mismatch case to reconcile, so the host relays opaque bytes it
/// neither reads nor verifies.
#[derive(Debug, Serialize)]
pub struct EnclaveAssignmentResponse {
    attestation: String,
}

/// Assigns this host's enclave by returning its encryption-key attestation.
///
/// Called by the authenticator immediately before it seals a match payload, so the
/// `Encryption Key` it seals to is the one this enclave attested during the same exchange.
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
                failure_class = failure_class(&error),
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
            // the enclave answered a request it was not asked, so surface it as a host bug
            // rather than folding it into retryable unavailability.
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        },
    }
}

/// Names the failure class for telemetry, so triage does not have to parse `Debug` output.
const fn failure_class(error: &EnclaveClientError) -> &'static str {
    match error {
        EnclaveClientError::Timeout => "timeout",
        EnclaveClientError::Transport(_) => "transport",
        EnclaveClientError::Operation(operation) => match operation {
            EnclaveError::NotReady => "enclave_not_ready",
            EnclaveError::SecureModuleNotInitialized => "nsm_unavailable",
            EnclaveError::AttestationFailed => "attestation_failed",
            _ => "unexpected_operation_error",
        },
    }
}

#[cfg(test)]
mod tests {
    use axum::{extract::State, http::StatusCode};
    use enclave_types::{EnclaveError, GetEnclaveKeysResponse};

    use super::{failure_class, handler, status_for};
    use crate::enclave::EnclaveClientError;
    use crate::test_support::{StubEnclaveClient, state_with};

    #[tokio::test]
    async fn returns_base64_of_the_encryption_key_attestation() {
        let state = state_with(StubEnclaveClient::returning_keys(GetEnclaveKeysResponse {
            encryption_key_attestation: vec![1, 2, 3],
            signing_key_attestation: vec![4, 5, 6],
        }));

        let response = handler(State(state))
            .await
            .expect("a reachable enclave should yield an assignment")
            .0;

        assert_eq!(response.attestation, "AQID");
    }

    #[tokio::test]
    async fn never_relays_the_signing_key_attestation() {
        let state = state_with(StubEnclaveClient::returning_keys(GetEnclaveKeysResponse {
            encryption_key_attestation: vec![1, 2, 3],
            signing_key_attestation: vec![4, 5, 6],
        }));

        let response = handler(State(state))
            .await
            .expect("a reachable enclave should yield an assignment")
            .0;

        let json = serde_json::to_value(&response).expect("response should serialize");
        assert_eq!(
            json.as_object().map(serde_json::Map::len),
            Some(1),
            "the assignment must expose the attestation and nothing else"
        );
        assert_ne!(response.attestation, "BAUG");
    }

    #[tokio::test]
    async fn maps_enclave_failure_to_its_status() {
        let state = state_with(StubEnclaveClient::failing(EnclaveClientError::Timeout));

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

        // A match-path error here means the enclave answered the wrong request.
        assert_eq!(
            status_for(&EnclaveClientError::Operation(EnclaveError::DecryptFailed)),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn failure_classes_are_distinct_per_status() {
        assert_eq!(failure_class(&EnclaveClientError::Timeout), "timeout");
        assert_eq!(
            failure_class(&EnclaveClientError::Transport("boom".to_string())),
            "transport"
        );
        assert_eq!(
            failure_class(&EnclaveClientError::Operation(EnclaveError::NotReady)),
            "enclave_not_ready"
        );
        assert_eq!(
            failure_class(&EnclaveClientError::Operation(
                EnclaveError::AttestationFailed
            )),
            "attestation_failed"
        );
    }
}

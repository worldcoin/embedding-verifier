use axum::{body::Bytes, extract::State, http::StatusCode};
use enclave_types::{self as enclave, EnclaveError};

use crate::enclave::EnclaveClientError;
use crate::types::AppState;

/// Forwards a sealed match request to the enclave and relays the sealed outcome.
///
/// Both directions are `application/octet-stream` and both are opaque here. The response
/// is sealed to a key derived from the client's own request context, so the host cannot
/// read the statement it carries.
pub async fn handler(State(state): State<AppState>, body: Bytes) -> Result<Vec<u8>, StatusCode> {
    if body.is_empty() {
        tracing::warn!("match request had an empty body");
        return Err(StatusCode::BAD_REQUEST);
    }

    let response = state
        .enclave_client()
        .run_match(enclave::MatchRequest {
            sealed_payload: body.to_vec(),
        })
        .await
        .map_err(|error| {
            let status = status_for(&error);
            if status.is_server_error() {
                tracing::error!(?error, %status, "match request failed");
            } else {
                tracing::warn!(?error, %status, "match request rejected");
            }
            status
        })?;

    Ok(response.sealed_outcome)
}

/// Maps an enclave-client failure to an HTTP status.
const fn status_for(error: &EnclaveClientError) -> StatusCode {
    match error {
        EnclaveClientError::Operation(operation) => match operation {
            EnclaveError::DecryptFailed
            | EnclaveError::MalformedMatchPayload
            | EnclaveError::InvalidHashesJson
            | EnclaveError::InvalidImage => StatusCode::BAD_REQUEST,
            // Well-formed request, but the match itself did not hold.
            EnclaveError::ThumbnailHashMismatch
            | EnclaveError::MatchBelowThreshold
            | EnclaveError::EmbeddingGenerationFailed => StatusCode::UNPROCESSABLE_ENTITY,
            EnclaveError::EmbeddingComparisonFailed | EnclaveError::EncryptFailed => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            EnclaveError::NotReady
            | EnclaveError::SecureModuleNotInitialized
            | EnclaveError::AttestationFailed => StatusCode::SERVICE_UNAVAILABLE,
        },
        EnclaveClientError::Timeout => StatusCode::GATEWAY_TIMEOUT,
        EnclaveClientError::Transport(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use axum::{body::Bytes, extract::State, http::StatusCode};
    use enclave_types::{self as enclave, EnclaveError, GetEnclaveKeysResponse};

    use super::{handler, status_for};
    use crate::enclave::{EnclaveClient, EnclaveClientError};
    use crate::types::{AppState, Environment};

    struct StubEnclaveClient {
        result: Result<enclave::MatchResponse, EnclaveClientError>,
    }

    #[async_trait]
    impl EnclaveClient for StubEnclaveClient {
        async fn health(&self) -> Result<(), EnclaveClientError> {
            Ok(())
        }

        async fn get_enclave_keys(&self) -> Result<GetEnclaveKeysResponse, EnclaveClientError> {
            Ok(GetEnclaveKeysResponse {
                encryption_key_attestation: Vec::new(),
                signing_key_attestation: Vec::new(),
            })
        }

        async fn run_match(
            &self,
            request: enclave::MatchRequest,
        ) -> Result<enclave::MatchResponse, EnclaveClientError> {
            assert_eq!(request.sealed_payload, b"sealed");
            self.result.clone()
        }
    }

    fn state_returning(result: Result<enclave::MatchResponse, EnclaveClientError>) -> AppState {
        AppState::new(
            Environment::Development,
            Arc::new(StubEnclaveClient { result }),
        )
    }

    fn sample_response() -> enclave::MatchResponse {
        enclave::MatchResponse {
            sealed_outcome: b"sealed-outcome".to_vec(),
        }
    }

    #[tokio::test]
    async fn relays_the_sealed_outcome_without_reading_it() {
        let state = state_returning(Ok(sample_response()));

        let body = handler(State(state), Bytes::from_static(b"sealed"))
            .await
            .expect("valid match should return a sealed outcome");

        assert_eq!(body, b"sealed-outcome");
    }

    #[tokio::test]
    async fn rejects_empty_body_with_bad_request() {
        let state = state_returning(Ok(sample_response()));

        let status = handler(State(state), Bytes::new())
            .await
            .expect_err("an empty body should be rejected");

        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn status_mapping_is_exhaustive_and_classified() {
        assert_eq!(
            status_for(&EnclaveClientError::Operation(EnclaveError::DecryptFailed)),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_for(&EnclaveClientError::Operation(
                EnclaveError::MalformedMatchPayload
            )),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_for(&EnclaveClientError::Operation(
                EnclaveError::InvalidHashesJson
            )),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_for(&EnclaveClientError::Operation(
                EnclaveError::MatchBelowThreshold
            )),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            status_for(&EnclaveClientError::Operation(EnclaveError::EncryptFailed)),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            status_for(&EnclaveClientError::Operation(EnclaveError::NotReady)),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            status_for(&EnclaveClientError::Timeout),
            StatusCode::GATEWAY_TIMEOUT
        );
        assert_eq!(
            status_for(&EnclaveClientError::Transport("boom".to_string())),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}

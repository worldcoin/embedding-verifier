use axum::{Json, extract::State, http::StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use enclave_types::{self as enclave, EnclaveError};
use serde::{Deserialize, Serialize};

use crate::enclave::EnclaveClientError;
use crate::types::AppState;

/// A match request from an HTTP client.
///
/// `sealed_payload` is base64-encoded ciphertext for the enclave transit key.
#[derive(Debug, Deserialize)]
pub struct MatchRequest {
    sealed_payload: String,
}

impl TryFrom<MatchRequest> for enclave::MatchRequest {
    type Error = base64::DecodeError;

    fn try_from(request: MatchRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            sealed_payload: STANDARD.decode(request.sealed_payload)?,
        })
    }
}

/// A match statement rendered for HTTP clients.
///
/// Binary fields are base64-encoded.
#[derive(Debug, Serialize)]
pub struct MatchStatement {
    version: u8,
    live_image_hash: String,
    credential_claim: String,
    challenger_image_hash: String,
    match_coefficient: f32,
}

/// A successful match response.
#[derive(Debug, Serialize)]
pub struct MatchResponse {
    statement: MatchStatement,
    signature: String,
}

impl From<enclave::MatchResponse> for MatchResponse {
    fn from(response: enclave::MatchResponse) -> Self {
        let enclave::MatchStatement {
            version,
            live_image_hash,
            credential_claim,
            challenger_image_hash,
            match_coefficient,
        } = response.statement;

        Self {
            statement: MatchStatement {
                version,
                live_image_hash: STANDARD.encode(live_image_hash),
                credential_claim: STANDARD.encode(credential_claim),
                challenger_image_hash: STANDARD.encode(challenger_image_hash),
                match_coefficient,
            },
            signature: STANDARD.encode(response.signature),
        }
    }
}

/// Forwards a sealed match request to the enclave.
pub async fn handler(
    State(state): State<AppState>,
    Json(body): Json<MatchRequest>,
) -> Result<Json<MatchResponse>, StatusCode> {
    let request: enclave::MatchRequest = body.try_into().map_err(|error| {
        tracing::warn!(
            ?error,
            "match request had a malformed base64 sealed payload"
        );
        StatusCode::BAD_REQUEST
    })?;

    let response = state
        .enclave_client()
        .run_match(request)
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

    Ok(Json(response.into()))
}

/// Maps an enclave-client failure to an HTTP status.
const fn status_for(error: &EnclaveClientError) -> StatusCode {
    match error {
        EnclaveClientError::Operation(operation) => match operation {
            // The client sealed a request the enclave could not use.
            EnclaveError::DecryptFailed
            | EnclaveError::MalformedMatchPayload
            | EnclaveError::InvalidHashesJson => StatusCode::BAD_REQUEST,
            // Well-formed request, but the match itself did not hold.
            EnclaveError::ThumbnailHashMismatch | EnclaveError::MatchBelowThreshold => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            // The enclave is reachable but not able to serve.
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
    use axum::{Json, extract::State, http::StatusCode};
    use enclave_types::{self as enclave, EnclaveError, GetTransitKeyResponse};

    use super::{MatchRequest, handler, status_for};
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

        async fn get_transit_key(&self) -> Result<GetTransitKeyResponse, EnclaveClientError> {
            Ok(GetTransitKeyResponse {
                attestation: Vec::new(),
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
            statement: enclave::MatchStatement {
                version: 1,
                live_image_hash: [1u8; 32],
                credential_claim: [2u8; 32],
                challenger_image_hash: [3u8; 32],
                match_coefficient: 1.0,
            },
            signature: vec![7u8; 64],
        }
    }

    #[tokio::test]
    async fn forwards_sealed_payload_and_encodes_statement() {
        let state = state_returning(Ok(sample_response()));
        let body = MatchRequest {
            sealed_payload: base64_of(b"sealed"),
        };

        let response = handler(State(state), Json(body))
            .await
            .expect("valid match should return a statement")
            .0;

        assert_eq!(response.statement.version, 1);
        assert_eq!(response.statement.live_image_hash, base64_of(&[1u8; 32]));
        assert_eq!(response.statement.credential_claim, base64_of(&[2u8; 32]));
        assert_eq!(
            response.statement.challenger_image_hash,
            base64_of(&[3u8; 32])
        );
        assert_eq!(
            response.statement.match_coefficient.to_bits(),
            1.0f32.to_bits()
        );
        assert_eq!(response.signature, base64_of(&[7u8; 64]));
    }

    #[tokio::test]
    async fn rejects_malformed_base64_with_bad_request() {
        let state = state_returning(Ok(sample_response()));
        let body = MatchRequest {
            sealed_payload: "not valid base64!!!".to_string(),
        };

        let status = handler(State(state), Json(body))
            .await
            .expect_err("malformed base64 should be rejected");

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

    fn base64_of(bytes: &[u8]) -> String {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        STANDARD.encode(bytes)
    }
}

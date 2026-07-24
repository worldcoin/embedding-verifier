use axum::{Json, extract::State, http::StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use enclave_types::{EnclaveError, MatchRequest, MatchResponse, MatchStatement};
use serde::{Deserialize, Serialize};

use crate::enclave::EnclaveClientError;
use crate::types::AppState;

/// A match request from an HTTP client.
///
/// The host is a thin forwarder: `sealed_payload` is an opaque X25519 sealed box the client
/// encrypts to the enclave transit key. It is base64 (standard alphabet, with padding) so it
/// survives JSON transport.
#[derive(Debug, Deserialize)]
pub struct MatchHttpRequest {
    sealed_payload: String,
}

/// A match statement rendered for HTTP clients.
///
/// The fixed-size hashes and the signature are base64-encoded opaque bytes, matching the
/// encoding used by the transit-key route.
#[derive(Debug, Serialize)]
pub struct MatchStatementResponse {
    version: u8,
    live_image_hash: String,
    credential_claim: String,
    challenger_image_hash: String,
    match_coefficient: f32,
}

/// A successful match response.
#[derive(Debug, Serialize)]
pub struct MatchHttpResponse {
    statement: MatchStatementResponse,
    signature: String,
}

impl From<MatchResponse> for MatchHttpResponse {
    fn from(response: MatchResponse) -> Self {
        let MatchStatement {
            version,
            live_image_hash,
            credential_claim,
            challenger_image_hash,
            match_coefficient,
        } = response.statement;

        Self {
            statement: MatchStatementResponse {
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

/// Forwards a sealed match request to the enclave and returns its signed statement.
///
/// The host never inspects the payload: it decodes the base64 envelope and relays the opaque
/// ciphertext. Enclave outcomes are mapped to HTTP status codes by [`status_for`].
pub async fn handler(
    State(state): State<AppState>,
    Json(body): Json<MatchHttpRequest>,
) -> Result<Json<MatchHttpResponse>, StatusCode> {
    let sealed_payload = STANDARD.decode(&body.sealed_payload).map_err(|error| {
        tracing::warn!(
            ?error,
            "match request had a malformed base64 sealed payload"
        );
        StatusCode::BAD_REQUEST
    })?;

    let response = state
        .enclave_client()
        .run_match(MatchRequest { sealed_payload })
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

/// Maps an enclave-client failure to the HTTP status returned to the caller.
///
/// Client-caused enclave errors surface as 4xx; enclave unavailability and transport faults
/// surface as 5xx so callers and probes can distinguish a bad request from a broken dependency.
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
    use enclave_types::{
        EnclaveError, GetTransitKeyResponse, MatchRequest, MatchResponse, MatchStatement,
    };

    use super::{MatchHttpRequest, handler, status_for};
    use crate::enclave::{EnclaveClient, EnclaveClientError};
    use crate::types::{AppState, Environment};

    /// Enclave client that returns a preconfigured match outcome.
    struct StubEnclaveClient {
        result: Result<MatchResponse, EnclaveClientError>,
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
            _request: MatchRequest,
        ) -> Result<MatchResponse, EnclaveClientError> {
            self.result.clone()
        }
    }

    fn state_returning(result: Result<MatchResponse, EnclaveClientError>) -> AppState {
        AppState::new(
            Environment::Development,
            Arc::new(StubEnclaveClient { result }),
        )
    }

    fn sample_response() -> MatchResponse {
        MatchResponse {
            statement: MatchStatement {
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
        let body = MatchHttpRequest {
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
        let body = MatchHttpRequest {
            sealed_payload: "not valid base64!!!".to_string(),
        };

        let status = handler(State(state), Json(body))
            .await
            .expect_err("malformed base64 should be rejected");

        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn maps_enclave_failure_to_status() {
        let state = state_returning(Err(EnclaveClientError::Operation(
            EnclaveError::MatchBelowThreshold,
        )));
        let body = MatchHttpRequest {
            sealed_payload: base64_of(b"sealed"),
        };

        let status = handler(State(state), Json(body))
            .await
            .expect_err("a below-threshold match should be an error");

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
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
                EnclaveError::ThumbnailHashMismatch
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

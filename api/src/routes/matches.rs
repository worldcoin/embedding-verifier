use axum::{
    body::Bytes,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use enclave_types::{self as enclave, AEAD_TAG_LEN, ENCAPPED_KEY_LEN, EnclaveError, MatchOutcome};

use crate::enclave::EnclaveClientError;
use crate::types::AppState;

/// Content type of both the request and response bodies.
const OCTET_STREAM: &str = "application/octet-stream";

/// Relays an HPKE-sealed match request to the enclave and returns the sealed response.
///
/// Both directions are opaque to this host. The request body is the client's encapsulated
/// key followed by the ciphertext; the response body is the enclave's sealed outcome,
/// which only the requesting client holds the key material to open. The host contributes
/// nothing but the HTTP status, derived from a coarse class the enclave binds into the
/// response AAD — rewriting it here would only break the client's decryption.
pub async fn handler(State(state): State<AppState>, body: Bytes) -> Result<Response, StatusCode> {
    let (enc, ciphertext) = split_request(&body)?;

    let response = state
        .enclave_client()
        .run_match(enclave::MatchRequest { enc, ciphertext })
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

    let status = match response.outcome {
        MatchOutcome::Statement => StatusCode::OK,
        // Well-formed request, but the match itself did not hold. The reason is inside
        // the body and readable only by the client.
        MatchOutcome::Rejected => StatusCode::UNPROCESSABLE_ENTITY,
    };

    Ok((
        status,
        [(header::CONTENT_TYPE, OCTET_STREAM)],
        response.ciphertext,
    )
        .into_response())
}

/// Splits the request body into the HPKE encapsulated key and the ciphertext.
///
/// The framing is positional because the host has no reason to parse a structure it
/// cannot read: a fixed-width `enc` for the pinned ciphersuite, then the rest. The length
/// floor rejects bodies that cannot possibly carry an authentication tag; everything
/// beyond that is the enclave's call.
fn split_request(body: &Bytes) -> Result<(Vec<u8>, Vec<u8>), StatusCode> {
    if body.len() <= ENCAPPED_KEY_LEN + AEAD_TAG_LEN {
        tracing::warn!(
            length = body.len(),
            "match request body is too short to be a sealed request"
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    let (enc, ciphertext) = body.split_at(ENCAPPED_KEY_LEN);

    Ok((enc.to_vec(), ciphertext.to_vec()))
}

/// Maps an enclave-client failure to an HTTP status.
const fn status_for(error: &EnclaveClientError) -> StatusCode {
    match error {
        EnclaveClientError::Operation(operation) => match operation {
            EnclaveError::BadRequest => StatusCode::BAD_REQUEST,
            EnclaveError::NotReady
            | EnclaveError::SecureModuleNotInitialized
            | EnclaveError::AttestationFailed
            | EnclaveError::Internal => StatusCode::SERVICE_UNAVAILABLE,
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
    use enclave_types::{
        self as enclave, AEAD_TAG_LEN, ENCAPPED_KEY_LEN, EnclaveError, GetTransitKeyResponse,
        MatchOutcome,
    };

    use super::{handler, split_request, status_for};
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
            assert_eq!(request.enc, vec![1u8; ENCAPPED_KEY_LEN]);
            assert_eq!(request.ciphertext, vec![2u8; AEAD_TAG_LEN + 1]);
            self.result.clone()
        }
    }

    fn state_returning(result: Result<enclave::MatchResponse, EnclaveClientError>) -> AppState {
        AppState::new(
            Environment::Development,
            Arc::new(StubEnclaveClient { result }),
        )
    }

    /// A body whose `enc` and ciphertext the stub asserts on.
    fn sealed_body() -> Bytes {
        let mut body = vec![1u8; ENCAPPED_KEY_LEN];
        body.extend_from_slice(&[2u8; AEAD_TAG_LEN + 1]);

        Bytes::from(body)
    }

    fn sealed_response(outcome: MatchOutcome) -> enclave::MatchResponse {
        enclave::MatchResponse {
            outcome,
            ciphertext: vec![9u8; 48],
        }
    }

    #[tokio::test]
    async fn returns_the_sealed_statement_verbatim() {
        let state = state_returning(Ok(sealed_response(MatchOutcome::Statement)));

        let response = handler(State(state), sealed_body())
            .await
            .expect("a sealed statement should be relayed");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .expect("content type should be set"),
            "application/octet-stream"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        assert_eq!(body.as_ref(), &[9u8; 48]);
    }

    #[tokio::test]
    async fn maps_a_sealed_rejection_to_unprocessable_entity() {
        let state = state_returning(Ok(sealed_response(MatchOutcome::Rejected)));

        let response = handler(State(state), sealed_body())
            .await
            .expect("a sealed rejection is still a response body");

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        // The reason travels in the body, sealed — the host adds nothing to it.
        assert_eq!(body.as_ref(), &[9u8; 48]);
    }

    #[tokio::test]
    async fn rejects_bodies_that_cannot_carry_a_sealed_request() {
        let state = state_returning(Ok(sealed_response(MatchOutcome::Statement)));

        for length in [0, ENCAPPED_KEY_LEN, ENCAPPED_KEY_LEN + AEAD_TAG_LEN] {
            let status = handler(State(state.clone()), Bytes::from(vec![0u8; length]))
                .await
                .expect_err("a short body should be rejected");

            assert_eq!(status, StatusCode::BAD_REQUEST, "length {length}");
        }
    }

    #[test]
    fn splits_the_body_at_the_encapsulated_key() {
        let (enc, ciphertext) = split_request(&sealed_body()).expect("body should split");

        assert_eq!(enc, vec![1u8; ENCAPPED_KEY_LEN]);
        assert_eq!(ciphertext, vec![2u8; AEAD_TAG_LEN + 1]);
    }

    #[test]
    fn status_mapping_is_exhaustive_and_classified() {
        assert_eq!(
            status_for(&EnclaveClientError::Operation(EnclaveError::BadRequest)),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_for(&EnclaveClientError::Operation(EnclaveError::Internal)),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            status_for(&EnclaveClientError::Operation(EnclaveError::NotReady)),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            status_for(&EnclaveClientError::Operation(
                EnclaveError::SecureModuleNotInitialized
            )),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            status_for(&EnclaveClientError::Operation(
                EnclaveError::AttestationFailed
            )),
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

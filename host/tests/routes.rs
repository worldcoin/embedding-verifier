//! Route tests driven through the real router.
//!
//! Requests go through `routes::handler()`, so the path and method each route is registered
//! under are covered alongside its behaviour.

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use common::{StubEnclaveClient, state_with};
use enclave_types::{EnclaveError, GetEnclaveKeysResponse};
use host::enclave::EnclaveClientError;
use host::routes;
use host::types::AppState;
use http_body_util::BodyExt as _;
use serde_json::Value;
use tower::ServiceExt as _;

/// Sends `request` through the router and returns the status and decoded JSON body.
async fn send(state: AppState, request: Request<Body>) -> (StatusCode, Value) {
    let response = routes::handler()
        .with_state(state)
        .oneshot(request)
        .await
        .expect("the router should answer");

    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("the body should be readable")
        .to_bytes();

    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("responses should be JSON")
    };

    (status, body)
}

fn assignment_request() -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/enclave-assignment")
        .body(Body::empty())
        .expect("request should be valid")
}

fn keys(encryption: Vec<u8>, signing: Vec<u8>) -> StubEnclaveClient {
    StubEnclaveClient {
        keys: Some(Ok(GetEnclaveKeysResponse {
            encryption_key_attestation: encryption,
            signing_key_attestation: signing,
        })),
        ..StubEnclaveClient::default()
    }
}

#[tokio::test]
async fn assignment_returns_the_encryption_key_attestation_and_nothing_else() {
    let state = state_with(keys(vec![1, 2, 3], vec![4, 5, 6]));

    let (status, body) = send(state, assignment_request()).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["attestation"], "AQID");
    assert_eq!(
        body.as_object().map(serde_json::Map::len),
        Some(1),
        "the assignment must expose the attestation and nothing else"
    );
}

#[tokio::test]
async fn assignment_is_not_reachable_by_get() {
    let state = state_with(keys(vec![1, 2, 3], vec![4, 5, 6]));

    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/enclave-assignment")
        .body(Body::empty())
        .expect("request should be valid");

    let (status, _) = send(state, request).await;

    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

/// Enclave keys are not exposed as their own route. The signing-key attestation belongs to
/// the Key Registry, and the encryption key is only served as part of an assignment.
#[tokio::test]
async fn enclave_keys_are_not_served_as_a_route() {
    let state = state_with(keys(vec![1, 2, 3], vec![4, 5, 6]));

    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/enclave/keys")
        .body(Body::empty())
        .expect("request should be valid");

    let (status, _) = send(state, request).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn assignment_surfaces_enclave_failures_as_structured_errors() {
    let cases = [
        (
            EnclaveClientError::Timeout,
            StatusCode::GATEWAY_TIMEOUT,
            "enclave_timeout",
            true,
        ),
        (
            EnclaveClientError::Transport("boom".to_string()),
            StatusCode::SERVICE_UNAVAILABLE,
            "enclave_unreachable",
            true,
        ),
        (
            EnclaveClientError::Operation(EnclaveError::NotReady),
            StatusCode::SERVICE_UNAVAILABLE,
            "enclave_not_ready",
            true,
        ),
        (
            EnclaveClientError::Operation(EnclaveError::DecryptFailed),
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            false,
        ),
    ];

    for (error, expected_status, expected_code, retryable) in cases {
        let state = state_with(StubEnclaveClient {
            keys: Some(Err(error)),
            ..StubEnclaveClient::default()
        });

        let (status, body) = send(state, assignment_request()).await;

        assert_eq!(status, expected_status, "for {expected_code}");
        assert_eq!(body["error"]["code"], expected_code);
        assert_eq!(body["allowRetry"], retryable, "for {expected_code}");
    }
}

#[tokio::test]
async fn matches_forwards_the_sealed_payload_and_returns_hex_fields() {
    let state = state_with(StubEnclaveClient {
        match_result: Some(Ok(enclave_types::MatchResponse {
            statement: enclave_types::MatchStatement {
                version: 1,
                live_image_hash: [1u8; 32],
                credential_claim: [2u8; 32],
                challenger_image_hash: [3u8; 32],
                match_coefficient: 1.0,
            },
            signature: vec![7u8; 64],
        })),
        expected_sealed_payload: Some(b"sealed".to_vec()),
        ..StubEnclaveClient::default()
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/matches")
        .body(Body::from("sealed"))
        .expect("request should be valid");

    let (status, body) = send(state, request).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["statement"]["version"], 1);
    assert_eq!(body["statement"]["live_image_hash"], hex::encode([1u8; 32]));
    assert_eq!(body["signature"], hex::encode([7u8; 64]));
}

#[tokio::test]
async fn matches_rejects_an_empty_body() {
    let state = state_with(StubEnclaveClient::default());

    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/matches")
        .body(Body::empty())
        .expect("request should be valid");

    let (status, body) = send(state, request).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_request");
}

/// The same enclave error is a client error here and a host bug on assignment.
#[tokio::test]
async fn matches_treats_a_decrypt_failure_as_a_client_error() {
    let state = state_with(StubEnclaveClient {
        match_result: Some(Err(EnclaveClientError::Operation(
            EnclaveError::DecryptFailed,
        ))),
        ..StubEnclaveClient::default()
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/matches")
        .body(Body::from("sealed"))
        .expect("request should be valid");

    let (status, body) = send(state, request).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_request");
}

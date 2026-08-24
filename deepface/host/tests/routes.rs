//! Route tests driven through the real router.
//!
//! Requests go through `routes::handler()`, so the path and method each route is registered
//! under are covered alongside its behaviour.

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::{StubChallengeSource, StubEnclaveClient, state_with, state_with_source};
use deepface_host::AppState;
use deepface_host::challenge_fetcher::FetchError;
use deepface_host::enclave::EnclaveClientError;
use deepface_host::routes;
use enclave_types::EnclaveError;
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

/// Builds a match request with a well-formed challenge URL.
fn match_request(url: &str) -> Request<Body> {
    let body = format!(
        r#"{{"challenge_image_url":"{url}","ciphertext":"{}"}}"#,
        STANDARD.encode("sealed")
    );

    Request::builder()
        .method(Method::POST)
        .uri("/v1/matches")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("request should be valid")
}

/// Serves only the encryption key. The stub panics on anything else, so this doubles as an
/// assertion that the assignment route asks for one key and not the other.
fn encryption_key(attestation: Vec<u8>) -> StubEnclaveClient {
    StubEnclaveClient {
        encryption_key: Some(Ok(attestation)),
        ..StubEnclaveClient::default()
    }
}

#[tokio::test]
async fn assignment_returns_the_encryption_key_attestation_and_nothing_else() {
    let state = state_with(encryption_key(vec![1, 2, 3]));

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
    let state = state_with(encryption_key(vec![1, 2, 3]));

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
    let state = state_with(encryption_key(vec![1, 2, 3]));

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
            EnclaveClientError::Operation(EnclaveError::RequestNotOpened),
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            false,
        ),
    ];

    for (error, expected_status, expected_code, retryable) in cases {
        let state = state_with(StubEnclaveClient {
            encryption_key: Some(Err(error)),
            ..StubEnclaveClient::default()
        });

        let (status, body) = send(state, assignment_request()).await;

        assert_eq!(status, expected_status, "for {expected_code}");
        assert_eq!(body["error"]["code"], expected_code);
        assert_eq!(body["allowRetry"], retryable, "for {expected_code}");
    }
}

/// Only the signing key is configured, so this also pins that the match route never asks for the
/// encryption key it has no use for.
#[tokio::test]
async fn matches_relays_the_sealed_request_and_the_fetched_challenge() {
    let state = state_with_source(
        StubEnclaveClient {
            signing_key: Some(Ok(vec![4, 5, 6])),
            match_result: Some(Ok(deepface_types::MatchResponse {
                ciphertext: vec![9u8; 48],
            })),
            expected_body: Some(b"sealed".to_vec()),
            expected_challenge: Some(b"challenge-ciphertext".to_vec()),
            ..StubEnclaveClient::default()
        },
        StubChallengeSource::returning(b"challenge-ciphertext"),
    );

    let (status, body) = send(
        state,
        match_request("https://bucket.example.com/challenge-images/a"),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    // Both fields are relayed opaquely: the host encodes, it does not interpret.
    assert_eq!(body["response_ciphertext"], STANDARD.encode([9u8; 48]));
    assert_eq!(body["key_attestation"], STANDARD.encode([4, 5, 6]));
}

#[tokio::test]
async fn matches_rejects_a_non_base64_ciphertext() {
    let state = state_with(StubEnclaveClient::default());

    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/matches")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"challenge_image_url":"https://bucket.example.com/challenge-images/a","ciphertext":"not base64!"}"#,
        ))
        .expect("request should be valid");

    let (status, body) = send(state, request).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_request");
}

#[tokio::test]
async fn matches_attributes_fetch_failures_outward() {
    // The RP's bucket is an availability dependency of this path, so its failures are a 502 and
    // never an enclave fault.
    let cases = [
        (
            FetchError::Unreachable,
            StatusCode::BAD_GATEWAY,
            "challenge_fetch_failed",
            true,
        ),
        (
            FetchError::TooLarge,
            StatusCode::BAD_GATEWAY,
            "challenge_fetch_failed",
            false,
        ),
        (
            FetchError::Malformed,
            StatusCode::BAD_REQUEST,
            "invalid_challenge_url",
            false,
        ),
    ];

    for (error, expected_status, expected_code, retryable) in cases {
        let state = state_with_source(
            StubEnclaveClient::default(),
            StubChallengeSource::failing(error),
        );

        let (status, body) = send(
            state,
            match_request("https://bucket.example.com/challenge-images/a"),
        )
        .await;

        assert_eq!(status, expected_status, "for {error:?}");
        assert_eq!(body["error"]["code"], expected_code, "for {error:?}");
        assert_eq!(body["allowRetry"], retryable, "for {error:?}");
    }
}

#[tokio::test]
async fn matches_maps_an_unopenable_request_to_conflict() {
    // Re-assign and re-seal: the client cannot tell this from a corrupt ciphertext, which is why
    // the retry has to be bounded client-side.
    let state = state_with(StubEnclaveClient {
        signing_key: Some(Ok(vec![2])),
        match_result: Some(Err(EnclaveClientError::Operation(
            EnclaveError::RequestNotOpened,
        ))),
        ..StubEnclaveClient::default()
    });

    let (status, body) = send(
        state,
        match_request("https://bucket.example.com/challenge-images/a"),
    )
    .await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "reassign_required");
}

#[tokio::test]
async fn matches_answers_200_whatever_the_sealed_result_says() {
    // A quality failure, a below-threshold match and a malformed payload are all sealed now, so
    // the host cannot distinguish them from a statement -- and must not try.
    let state = state_with(StubEnclaveClient {
        signing_key: Some(Ok(vec![2])),
        match_result: Some(Ok(deepface_types::MatchResponse {
            ciphertext: vec![9u8; 48],
        })),
        ..StubEnclaveClient::default()
    });

    let (status, body) = send(
        state,
        match_request("https://bucket.example.com/challenge-images/a"),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["response_ciphertext"], STANDARD.encode([9u8; 48]));
    assert_eq!(
        body.as_object().map(serde_json::Map::len),
        Some(2),
        "the relay exposes the ciphertext and the attestation, nothing else"
    );
}

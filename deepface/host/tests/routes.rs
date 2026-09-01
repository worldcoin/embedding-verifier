//! Route tests driven through the real router.
//!
//! Requests go through `routes::handler()`, so the path and method each route is registered
//! under are covered alongside its behaviour.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::{FailingChallengeStore, StubEnclaveClient, state_with, state_with_store};
use deepface_host::AppState;
use deepface_host::challenge_store::{
    ChallengeStore, InMemoryChallengeStore, MAX_CHALLENGE_BYTES, StoreError,
};
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
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
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

/// Builds a challenge push carrying `ciphertext` as its raw body.
fn challenge_request(ciphertext: &[u8]) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/challenges")
        .header("content-type", "application/octet-stream")
        .body(Body::from(ciphertext.to_vec()))
        .expect("request should be valid")
}

/// Builds a match request naming a stored challenge.
fn match_request(challenge_id: &str) -> Request<Body> {
    let body = format!(
        r#"{{"challenge_id":"{challenge_id}","ciphertext":"{}"}}"#,
        STANDARD.encode("sealed")
    );

    Request::builder()
        .method(Method::POST)
        .uri("/v1/matches")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("request should be valid")
}

/// Stores a challenge blob and returns the id a match can name it by.
async fn stored_challenge(store: &InMemoryChallengeStore, bytes: &[u8]) -> String {
    store
        .put(bytes.to_vec())
        .await
        .expect("the in-memory store should accept a test blob")
        .to_string()
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

#[tokio::test]
async fn challenges_stores_a_blob_and_returns_its_id() {
    let state = state_with(StubEnclaveClient::default());

    let (status, body) = send(state, challenge_request(b"challenge-ciphertext")).await;

    assert_eq!(status, StatusCode::CREATED);
    let id = body["challenge_id"]
        .as_str()
        .expect("id should be a string");
    assert_eq!(id.len(), 32, "ids are 32 hex characters");
    assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(
        body.as_object().map(serde_json::Map::len),
        Some(1),
        "the push returns the id and nothing else"
    );
}

#[tokio::test]
async fn challenges_rejects_an_empty_body() {
    let state = state_with(StubEnclaveClient::default());

    let (status, body) = send(state, challenge_request(b"")).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_challenge");
}

#[tokio::test]
async fn challenges_refuses_an_oversized_blob() {
    let state = state_with(StubEnclaveClient::default());

    // One byte over the cap. Axum's body limit answers without an error envelope; the status
    // is the contract.
    let (status, _) = send(
        state,
        challenge_request(&vec![0u8; MAX_CHALLENGE_BYTES + 1]),
    )
    .await;

    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn challenges_attributes_a_full_store_outward() {
    let state = state_with_store(
        StubEnclaveClient::default(),
        Arc::new(FailingChallengeStore {
            error: StoreError::Full,
        }),
    );

    let (status, body) = send(state, challenge_request(b"challenge-ciphertext")).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], "challenge_store_full");
    assert_eq!(body["allowRetry"], true);
}

/// Only the signing key is configured, so this also pins that the match route never asks for the
/// encryption key it has no use for.
#[tokio::test]
async fn matches_relays_the_sealed_request_and_the_stored_challenge() {
    let store = Arc::new(InMemoryChallengeStore::new());
    let challenge_id = stored_challenge(&store, b"challenge-ciphertext").await;
    let state = state_with_store(
        StubEnclaveClient {
            signing_key: Some(Ok(vec![4, 5, 6])),
            match_result: Some(Ok(deepface_types::MatchResponse {
                ciphertext: vec![9u8; 48],
            })),
            expected_body: Some(b"sealed".to_vec()),
            expected_challenge: Some(b"challenge-ciphertext".to_vec()),
            ..StubEnclaveClient::default()
        },
        store,
    );

    let (status, body) = send(state, match_request(&challenge_id)).await;

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
            r#"{"challenge_id":"00112233445566778899aabbccddeeff","ciphertext":"not base64!"}"#,
        ))
        .expect("request should be valid");

    let (status, body) = send(state, request).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_request");
}

#[tokio::test]
async fn matches_rejects_a_malformed_challenge_id() {
    let state = state_with(StubEnclaveClient::default());

    let (status, body) = send(state, match_request("not-a-challenge-id")).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_challenge_id");
}

#[tokio::test]
async fn matches_answers_404_for_a_challenge_that_was_never_pushed() {
    // Terminal for the caller: the RP has to issue a fresh challenge, so no retry can succeed.
    let state = state_with(StubEnclaveClient::default());

    let (status, body) = send(state, match_request("00112233445566778899aabbccddeeff")).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "unknown_challenge");
    assert_eq!(body["allowRetry"], false);
}

#[tokio::test]
async fn matches_never_reports_a_store_outage_as_an_unknown_challenge() {
    let state = state_with_store(
        StubEnclaveClient::default(),
        Arc::new(FailingChallengeStore {
            error: StoreError::Unavailable("boom".to_owned()),
        }),
    );

    let (status, body) = send(state, match_request("00112233445566778899aabbccddeeff")).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], "challenge_store_unavailable");
    assert_eq!(body["allowRetry"], true);
}

#[tokio::test]
async fn matches_maps_an_unopenable_request_to_conflict() {
    // Re-assign and re-seal: the client cannot tell this from a corrupt ciphertext, which is why
    // the retry has to be bounded client-side.
    let store = Arc::new(InMemoryChallengeStore::new());
    let challenge_id = stored_challenge(&store, b"challenge-ciphertext").await;
    let state = state_with_store(
        StubEnclaveClient {
            signing_key: Some(Ok(vec![2])),
            match_result: Some(Err(EnclaveClientError::Operation(
                EnclaveError::RequestNotOpened,
            ))),
            ..StubEnclaveClient::default()
        },
        store,
    );

    let (status, body) = send(state, match_request(&challenge_id)).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "reassign_required");
}

#[tokio::test]
async fn matches_answers_200_whatever_the_sealed_result_says() {
    // A quality failure, a below-threshold match and a malformed payload are all sealed now, so
    // the host cannot distinguish them from a statement -- and must not try.
    let store = Arc::new(InMemoryChallengeStore::new());
    let challenge_id = stored_challenge(&store, b"challenge-ciphertext").await;
    let state = state_with_store(
        StubEnclaveClient {
            signing_key: Some(Ok(vec![2])),
            match_result: Some(Ok(deepface_types::MatchResponse {
                ciphertext: vec![9u8; 48],
            })),
            ..StubEnclaveClient::default()
        },
        store,
    );

    let (status, body) = send(state, match_request(&challenge_id)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["response_ciphertext"], STANDARD.encode([9u8; 48]));
    assert_eq!(
        body.as_object().map(serde_json::Map::len),
        Some(2),
        "the relay exposes the ciphertext and the attestation, nothing else"
    );
}

/// The push-then-match round trip through the real router and the real store: what an RP and
/// an authenticator do between them.
#[tokio::test]
async fn a_pushed_challenge_is_the_one_the_enclave_receives() {
    let store = Arc::new(InMemoryChallengeStore::new());
    let state = state_with_store(
        StubEnclaveClient {
            signing_key: Some(Ok(vec![2])),
            match_result: Some(Ok(deepface_types::MatchResponse {
                ciphertext: vec![9u8; 48],
            })),
            expected_challenge: Some(b"rp-pushed-bytes".to_vec()),
            ..StubEnclaveClient::default()
        },
        store,
    );

    let (status, body) = send(state.clone(), challenge_request(b"rp-pushed-bytes")).await;
    assert_eq!(status, StatusCode::CREATED);
    let challenge_id = body["challenge_id"]
        .as_str()
        .expect("id should be a string")
        .to_owned();

    let (status, _) = send(state, match_request(&challenge_id)).await;
    assert_eq!(status, StatusCode::OK);
}

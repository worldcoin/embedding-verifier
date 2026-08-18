//! End-to-end tests for the assignment client, over real HTTP.
//!
//! These drive [`Client`] against a stub host on a real TCP socket, so the JSON contract,
//! the base64 hop, and the verifier are exercised together rather than in isolation.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::http::StatusCode;
use axum::routing::post;
use hex_literal::hex;
use verifier_client::http::{Client, ClientError};
use verifier_client::nitro::{EnclaveAttestationVerifier, PcrMeasurement};

/// A real attestation document captured from a live Nitro enclave.
const REAL_ATTESTATION_DOC_BASE64: &str =
    include_str!("../src/nitro/testdata/real_attestation_doc.b64");

/// When the fixture was produced, per its own `timestamp` field (2025-09-23T11:56:49.915Z).
///
/// Its certificate chain is only valid for a few hours around this instant, so the tests pin
/// the clock here rather than using the wall clock.
const FIXTURE_TIMESTAMP_MILLIS: u64 = 1_758_628_609_915;

fn fixture_instant() -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(FIXTURE_TIMESTAMP_MILLIS)
}

/// The PCRs the fixture's enclave reported.
fn fixture_pcr_config() -> Vec<PcrMeasurement> {
    vec![
        PcrMeasurement::new(
            0,
            hex!(
                "108b32466f5dc0a9971e0bc8e3e4074e7821bb2dcad3841bdec9a08b30f173386f0394a01486df181f316b39443dab34"
            ),
        ),
        PcrMeasurement::new(
            1,
            hex!(
                "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493"
            ),
        ),
    ]
}

fn verifier() -> EnclaveAttestationVerifier {
    // Ten years, so the fixture is never rejected for staleness.
    EnclaveAttestationVerifier::new(vec![fixture_pcr_config()], 10 * 365 * 24 * 60 * 60 * 1000)
}

/// Serves `router` on an ephemeral port and returns its base URL.
async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("should bind an ephemeral port");
    let address = listener
        .local_addr()
        .expect("listener should have an address");

    tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("stub should run");
    });

    format!("http://{address}")
}

/// A stub host that answers assignments exactly as the real one does.
async fn serve_assignment(body: &'static str) -> String {
    serve(Router::new().route(
        "/v1/enclave-assignment",
        post(move || async move {
            (
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body,
            )
        }),
    ))
    .await
}

#[tokio::test]
async fn fetches_and_verifies_an_assignment_over_http() {
    let body: &'static str = Box::leak(
        format!(
            r#"{{"attestation":"{}"}}"#,
            REAL_ATTESTATION_DOC_BASE64.trim()
        )
        .into_boxed_str(),
    );
    let base_url = serve_assignment(body).await;

    let verified = Client::new(&base_url, verifier())
        .expect("client should build")
        .request_assignment(fixture_instant())
        .await
        .expect("a well-formed assignment should verify");

    assert_eq!(verified.timestamp_millis, FIXTURE_TIMESTAMP_MILLIS);
    assert!(verified.module_id.contains("-enc"));
    assert_eq!(verified.enclave_public_key.len(), 32);
}

#[tokio::test]
async fn rejects_an_assignment_whose_attestation_does_not_verify() {
    // A syntactically fine response carrying a document signed by nobody.
    let base_url = serve_assignment(r#"{"attestation":"hEBAQEA="}"#).await;

    let error = Client::new(&base_url, verifier())
        .expect("client should build")
        .request_assignment(fixture_instant())
        .await
        .expect_err("an unverifiable document must not be accepted");

    assert!(
        matches!(error, ClientError::Attestation(_)),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn surfaces_a_host_error_status_rather_than_retrying() {
    let base_url = serve(Router::new().route(
        "/v1/enclave-assignment",
        post(|| async { StatusCode::SERVICE_UNAVAILABLE }),
    ))
    .await;

    let error = Client::new(&base_url, verifier())
        .expect("client should build")
        .request_assignment(fixture_instant())
        .await
        .expect_err("a 503 should surface to the caller");

    assert!(
        matches!(error, ClientError::Status { status: 503 }),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn rejects_a_response_that_is_not_the_documented_json() {
    let base_url = serve_assignment(r#"{"unexpected":"shape"}"#).await;

    let error = Client::new(&base_url, verifier())
        .expect("client should build")
        .request_assignment(fixture_instant())
        .await
        .expect_err("a response missing the attestation field must be rejected");

    assert!(
        matches!(error, ClientError::MalformedResponse(_)),
        "unexpected error: {error}"
    );
}

#[test]
fn rejects_an_empty_base_url() {
    let error = Client::new("", verifier()).expect_err("an empty base URL is unusable");

    assert!(
        matches!(error, ClientError::InvalidBaseUrl(_)),
        "unexpected error: {error}"
    );
}

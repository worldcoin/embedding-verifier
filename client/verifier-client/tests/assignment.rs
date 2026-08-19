//! End-to-end tests for the assignment client, over real HTTP.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::http::StatusCode;
use axum::routing::post;
use hex_literal::hex;
use verifier_client::nitro::PcrMeasurement;
use verifier_client::{Client, ClientError, Config};

const REAL_ATTESTATION_DOC_BASE64: &str =
    include_str!("../src/nitro/testdata/real_attestation_doc.b64");

/// When the fixture was produced (2025-09-23T11:56:49.915Z). Its chain is valid only for a
/// few hours around this instant, so tests pin the clock here.
const FIXTURE_TIMESTAMP_MILLIS: u64 = 1_758_628_609_915;

fn fixture_instant() -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(FIXTURE_TIMESTAMP_MILLIS)
}

fn config(base_url: &str) -> Config {
    let pcrs = vec![PcrMeasurement::new(
        0,
        hex!(
            "108b32466f5dc0a9971e0bc8e3e4074e7821bb2dcad3841bdec9a08b30f173386f0394a01486df181f316b39443dab34"
        ),
    )];

    // Ten years, so the fixture is never rejected for staleness.
    Config::new(
        base_url,
        vec![pcrs],
        Duration::from_secs(10 * 365 * 24 * 60 * 60),
        false,
    )
    .expect("config should be valid")
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

/// A stub host answering assignments as the real one does.
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

    let verified = Client::new(config(&base_url))
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

    let error = Client::new(config(&base_url))
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

    let error = Client::new(config(&base_url))
        .expect("client should build")
        .request_assignment(fixture_instant())
        .await
        .expect_err("a 503 should surface to the caller");

    assert!(
        matches!(error, ClientError::Status { status: 503, .. }),
        "unexpected error: {error}"
    );
}

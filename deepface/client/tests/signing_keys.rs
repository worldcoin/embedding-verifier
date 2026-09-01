//! End-to-end tests for the signing-key lookup, over real HTTP.
//!
//! The property worth guarding is the taxonomy: a key this `Service` never issued is `Ok(None)`,
//! and a registry that could not be read is an error. Collapsing the second into the first would
//! let an outage read as a confident "no such key".

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use deepface_client::nitro::PcrMeasurement;
use deepface_client::{ClientError, Config, FaceVerifierClient};
use hex_literal::hex;

/// Reaches into `attested-channel`'s fixtures rather than keeping a second copy: the document
/// has to be a real signed one, and two copies would drift. A move breaks the build.
const REAL_ATTESTATION_DOC_BASE64: &str =
    include_str!("../../../shared/attested-channel/src/nitro/testdata/real_attestation_doc.b64");

/// When the fixture was produced (2025-09-23T11:56:49.915Z). Its chain is valid only for a
/// few hours around this instant, so tests pin the clock here.
const FIXTURE_TIMESTAMP_MILLIS: u64 = 1_758_628_609_915;

/// The key the fixture document attests. Any other key is a substitution.
const FIXTURE_ATTESTED_KEY: [u8; 32] =
    hex!("43b986461bbdb752dd389e8f36312e5ebc3377f91e694d8125d1bc0079b2e122");

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

    Config::new(base_url, vec![pcrs])
        .expect("config should be valid")
        // Ten years, so the fixture is never rejected for staleness.
        .with_max_attestation_age(Duration::from_secs(10 * 365 * 24 * 60 * 60))
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

/// A stub registry answering every lookup with `body`.
async fn serve_row(body: serde_json::Value) -> String {
    serve(Router::new().route(
        "/v1/signing-keys/{public_key}",
        get(move || {
            let body = body.clone();
            async move { axum::Json(body) }
        }),
    ))
    .await
}

fn row(status: &str) -> serde_json::Value {
    serde_json::json!({
        "public_key": format!("0x{}", hex::encode(FIXTURE_ATTESTED_KEY)),
        "attestation": REAL_ATTESTATION_DOC_BASE64.trim(),
        "pcr0": "0x00",
        "valid_from": 1_758_628_609u64,
        "retired_at": serde_json::Value::Null,
        "status": status,
    })
}

fn key_hex() -> String {
    format!("0x{}", hex::encode(FIXTURE_ATTESTED_KEY))
}

/// A key the `Service` never issued is not an error, and must not be reported as one.
#[tokio::test]
async fn an_unknown_key_is_absent_rather_than_an_error() {
    let base_url = serve(Router::new().route(
        "/v1/signing-keys/{public_key}",
        get(|| async { StatusCode::NOT_FOUND }),
    ))
    .await;

    let found = FaceVerifierClient::new(config(&base_url))
        .expect("client should build")
        .signing_key(&key_hex(), fixture_instant())
        .await
        .expect("a 404 is an answer, not a failure");

    assert!(found.is_none());
}

/// The other half of the taxonomy: an unreadable registry must never read as "unknown key".
#[tokio::test]
async fn an_unreachable_registry_is_an_error_not_an_absent_key() {
    let base_url = serve(Router::new().route(
        "/v1/signing-keys/{public_key}",
        get(|| async { StatusCode::SERVICE_UNAVAILABLE }),
    ))
    .await;

    let error = FaceVerifierClient::new(config(&base_url))
        .expect("client should build")
        .signing_key(&key_hex(), fixture_instant())
        .await
        .expect_err("a 503 must not be reported as an absent key");

    assert!(
        matches!(error, ClientError::Status(503)),
        "unexpected error: {error}"
    );
}

/// The host is untrusted, so a document attesting some other key is a substitution attempt.
#[tokio::test]
async fn rejects_a_row_attesting_a_different_key() {
    let base_url = serve_row(row("active")).await;
    let other_key = format!("0x{}", hex::encode([0x11u8; 32]));

    let error = FaceVerifierClient::new(config(&base_url))
        .expect("client should build")
        .signing_key(&other_key, fixture_instant())
        .await
        .expect_err("a document for another key must not be accepted");

    assert!(
        matches!(error, ClientError::SigningKeyMismatch),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn rejects_a_row_whose_attestation_does_not_verify() {
    let mut body = row("active");
    body["attestation"] = serde_json::Value::String("hEBAQEA=".to_owned());
    let base_url = serve_row(body).await;

    let error = FaceVerifierClient::new(config(&base_url))
        .expect("client should build")
        .signing_key(&key_hex(), fixture_instant())
        .await
        .expect_err("an unverifiable document must not be accepted");

    assert!(
        matches!(error, ClientError::Attestation(_)),
        "unexpected error: {error}"
    );
}

/// Refused before any request is made, so a typo cannot be answered by the host at all.
#[tokio::test]
async fn refuses_a_key_that_is_not_thirty_two_bytes_of_hex() {
    let base_url = serve_row(row("active")).await;
    let client = FaceVerifierClient::new(config(&base_url)).expect("client should build");

    for id in ["0xnothex", "0xab", ""] {
        let error = client
            .signing_key(id, fixture_instant())
            .await
            .expect_err("a malformed key is not a lookup");

        assert!(
            matches!(error, ClientError::InvalidSigningKeyId),
            "unexpected error for {id:?}: {error}"
        );
    }
}

/// The shared fixture attests an HPKE encryption key, not a `BabyJubJub` signing key, so it
/// stands in for a row whose document attests something unusable. A real signing-key fixture
/// would be needed to cover the accepting path; `matches.rs` skips `Success` for the same reason.
#[tokio::test]
async fn rejects_a_row_whose_attested_key_is_not_a_signing_key() {
    let base_url = serve_row(row("active")).await;

    let error = FaceVerifierClient::new(config(&base_url))
        .expect("client should build")
        .signing_key(&key_hex(), fixture_instant())
        .await
        .expect_err("a key that is not a curve point cannot verify anything");

    assert!(
        matches!(error, ClientError::InvalidSigningKey),
        "unexpected error: {error}"
    );
}

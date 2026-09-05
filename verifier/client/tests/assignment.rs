//! End-to-end tests for the assignment client, over real HTTP.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use flamingo_verifier_client as client;
use flamingo_verifier_client::PcrMeasurement;
use flamingo_verifier_client::{Config, FaceVerifierClient};
use hex_literal::hex;

fn config(base_url: &str) -> Config {
    let pcrs = vec![PcrMeasurement::new(
        0,
        hex!(
            "108b32466f5dc0a9971e0bc8e3e4074e7821bb2dcad3841bdec9a08b30f173386f0394a01486df181f316b39443dab34"
        ),
    )];

    Config::new(base_url, vec![pcrs]).expect("config should be valid")
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

/// A stub host answering assignments as the real one does, recording what it was sent.
async fn serve_assignment(
    attestation: &str,
    public_key: &str,
) -> (String, Arc<Mutex<Option<HeaderMap>>>) {
    let body = serde_json::json!({ "attestation": attestation, "public_key": public_key });
    let seen: Arc<Mutex<Option<HeaderMap>>> = Arc::new(Mutex::new(None));

    let router = Router::new()
        .route(
            "/v1/enclave-assignment",
            post(
                |State(seen): State<Arc<Mutex<Option<HeaderMap>>>>, headers: HeaderMap| async move {
                    *seen.lock().expect("lock should be held") = Some(headers);

                    axum::Json(body)
                },
            ),
        )
        .with_state(Arc::clone(&seen));

    (serve(router).await, seen)
}

/// The value the recorded request carried for `name`.
fn sent(seen: &Mutex<Option<HeaderMap>>, name: &str) -> Option<String> {
    seen.lock()
        .expect("lock should be held")
        .as_ref()
        .expect("the route should have been called")
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

#[tokio::test]
async fn rejects_an_assignment_whose_attestation_does_not_verify() {
    // A syntactically fine response carrying a document signed by nobody.
    let (base_url, _) = serve_assignment("hEBAQEA=", "a2V5").await;

    let error = FaceVerifierClient::new(config(&base_url))
        .expect("client should build")
        .request_assignment()
        .await
        .expect_err("an unverifiable document must not be accepted");

    assert!(
        matches!(error, client::Error::Channel(_)),
        "unexpected error: {error}"
    );
}

/// A gateway in front of the host authenticates the caller, so both kinds of header have to
/// arrive, and the one bound to this request has to beat the configured one.
#[tokio::test]
async fn carries_configured_and_per_request_headers() {
    let (base_url, seen) = serve_assignment("hEBAQEA=", "a2V5").await;
    let config = config(&base_url)
        .with_headers([
            ("client-name", "world-app"),
            ("integrity-token", "configured"),
        ])
        .expect("configured headers should be valid");

    FaceVerifierClient::new(config)
        .expect("client should build")
        .with_request_headers([("integrity-token", "per-request")])
        .expect("per-request headers should be valid")
        .request_assignment()
        .await
        .expect_err("headers must be sent even when the evidence is then rejected");

    assert_eq!(sent(&seen, "client-name").as_deref(), Some("world-app"));
    assert_eq!(
        sent(&seen, "integrity-token").as_deref(),
        Some("per-request")
    );
}

#[tokio::test]
async fn rejects_malformed_base64_in_either_assignment_field() {
    for (document, key) in [("!", "a2V5"), ("hEBAQEA=", "!")] {
        let (base_url, _) = serve_assignment(document, key).await;
        let error = FaceVerifierClient::new(config(&base_url))
            .unwrap()
            .request_assignment()
            .await
            .unwrap_err();
        assert!(matches!(error, client::Error::MalformedAssignment));
    }
}

#[tokio::test]
async fn surfaces_a_host_error_status_rather_than_retrying() {
    let base_url = serve(Router::new().route(
        "/v1/enclave-assignment",
        post(|| async { StatusCode::SERVICE_UNAVAILABLE }),
    ))
    .await;

    let error = FaceVerifierClient::new(config(&base_url))
        .expect("client should build")
        .request_assignment()
        .await
        .expect_err("a 503 should surface to the caller");

    assert!(
        matches!(error, client::Error::Status(503)),
        "unexpected error: {error}"
    );
}

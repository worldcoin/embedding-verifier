use std::sync::Arc;

use api::{
    config::Config,
    enclave::PontifexEnclaveClient,
    readiness::{Condition, Readiness},
    routes,
    telemetry::Metrics,
    types::AppState,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

fn state(readiness: Arc<Readiness>) -> AppState {
    AppState::new(
        Arc::new(Config::default()),
        Arc::new(PontifexEnclaveClient::new(0, 0)),
        readiness,
        Arc::new(Metrics::disabled()),
    )
}

async fn get(readiness: Arc<Readiness>, path: &str) -> (StatusCode, String) {
    let response = routes::handler(state(readiness))
        .oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should succeed");

    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should read");

    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn liveness_is_ok_even_when_the_enclave_is_unreachable() {
    // Readiness has no conditions met, so the enclave is effectively down.
    let (status, _) = get(Arc::new(Readiness::new()), "/healthz").await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn readiness_fails_closed_and_names_the_unmet_condition() {
    let (status, body) = get(Arc::new(Readiness::new()), "/readyz").await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("enclave_reachable"), "{body}");
}

#[tokio::test]
async fn readiness_is_ok_once_every_condition_holds() {
    let readiness = Arc::new(Readiness::new());
    readiness.set(Condition::EnclaveReachable, true);

    let (status, _) = get(readiness, "/readyz").await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn legacy_probe_paths_still_answer() {
    // The running deployment probes these; they come out once its values move.
    let readiness = Arc::new(Readiness::new());
    readiness.set(Condition::EnclaveReachable, true);

    assert_eq!(
        get(Arc::clone(&readiness), "/health").await.0,
        StatusCode::OK
    );
    assert_eq!(get(readiness, "/ready").await.0, StatusCode::OK);
}

use std::sync::Arc;

use axum::{body::Body, http::Request};
use deepface_host::key_registry::InMemoryKeyRegistry;
use deepface_host::{
    AppState, Environment, challenge_fetcher::ChallengeFetcher, enclave::PontifexEnclaveClient,
    routes,
};
use tokio::sync::watch;
use tower::ServiceExt;

/// Liveness, not readiness: it answers with no enclave, no registry and no registered key.
#[tokio::test]
async fn health_returns_ok() {
    let (_registered, watch_registered) = watch::channel(None);
    let state = AppState::new(
        Environment::Development,
        Arc::new(PontifexEnclaveClient::new(0, 0)),
        Arc::new(
            ChallengeFetcher::new("https://bucket.example.com/challenges/")
                .expect("the fetcher should build"),
        ),
        Arc::new(InMemoryKeyRegistry::new()),
        watch_registered,
    );
    let response = routes::handler()
        .with_state(state)
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("health request should be valid"),
        )
        .await
        .expect("health request should succeed");

    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

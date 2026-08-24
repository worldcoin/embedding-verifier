use std::sync::Arc;

use axum::{body::Body, http::Request};
use host::{
    AppState, Environment, challenge_fetcher::ChallengeFetcher, enclave::PontifexEnclaveClient,
    routes,
};
use tower::ServiceExt;

#[tokio::test]
async fn health_returns_ok() {
    let state = AppState::new(
        Environment::Development,
        Arc::new(PontifexEnclaveClient::new(0, 0)),
        Arc::new(
            ChallengeFetcher::new("https://bucket.example.com/challenges/")
                .expect("the fetcher should build"),
        ),
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

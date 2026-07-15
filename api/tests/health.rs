//! Health-route integration tests.

use api::{routes, types::Environment};
use axum::{body::Body, http::Request};
use tower::ServiceExt;

#[tokio::test]
async fn health_returns_ok() {
    let response = routes::handler()
        .with_state(Environment::Development)
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

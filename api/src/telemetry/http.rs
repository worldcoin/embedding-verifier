//! HTTP-layer telemetry: request correlation and per-request metrics.

use std::time::Instant;

use axum::{
    extract::{MatchedPath, Request, State},
    middleware::Next,
    response::Response,
};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tracing::field::Empty;

use crate::telemetry::metrics;
use crate::types::AppState;

const AMZN_TRACE_ID: &str = "x-amzn-trace-id";
const REQUEST_ID: &str = "x-request-id";

/// Accepts an inbound `x-request-id`, or mints one when the caller sent none.
#[must_use]
pub fn set_request_id_layer() -> SetRequestIdLayer<MakeRequestUuid> {
    SetRequestIdLayer::x_request_id(MakeRequestUuid)
}

/// Echoes the correlation id back to the caller.
#[must_use]
pub fn propagate_request_id_layer() -> PropagateRequestIdLayer {
    PropagateRequestIdLayer::x_request_id()
}

/// Opens a span carrying the identifiers triage starts from.
///
/// `x-amzn-trace-id` is recorded because it is the only key joining an application log line
/// to the ALB access log entry for the same request.
pub fn make_span(request: &Request) -> tracing::Span {
    let span = tracing::info_span!(
        "http",
        method = %request.method(),
        path = %request.uri().path(),
        request_id = Empty,
        amzn_trace_id = Empty,
    );

    if let Some(value) = header(request, REQUEST_ID) {
        span.record("request_id", value);
    }
    if let Some(value) = header(request, AMZN_TRACE_ID) {
        span.record("amzn_trace_id", value);
    }

    span
}

/// Records request count and latency, tagged by matched route.
///
/// Tagging by raw path would give every distinct `{public_key}` its own time series.
pub async fn record_metrics(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let route = matched_route(&request);
    let started = Instant::now();

    let response = next.run(request).await;

    let status = response.status();
    let class = if status.is_server_error() {
        "internal"
    } else if status.is_client_error() {
        "client"
    } else {
        "ok"
    };
    let status_text = status.as_u16().to_string();

    state.metrics().count(
        metrics::HTTP_REQUEST,
        &[
            ("route", route.as_str()),
            ("status", status_text.as_str()),
            ("class", class),
        ],
    );
    state.metrics().timing(
        metrics::HTTP_REQUEST_LATENCY,
        started.elapsed(),
        &[("route", route.as_str())],
    );

    response
}

fn matched_route(request: &Request) -> String {
    request.extensions().get::<MatchedPath>().map_or_else(
        || "unmatched".to_owned(),
        |matched| matched.as_str().to_owned(),
    )
}

fn header<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request.headers().get(name)?.to_str().ok()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{Router, body::Body, http::Request, middleware, routing::get};
    use tower::ServiceExt;

    use super::record_metrics;
    use crate::config::Config;
    use crate::enclave::PontifexEnclaveClient;
    use crate::readiness::Readiness;
    use crate::telemetry::Metrics;
    use crate::types::AppState;

    #[tokio::test]
    async fn requests_are_tagged_with_the_matched_route_not_the_raw_path() {
        let (metrics, emitted) = Metrics::recording();
        let state = AppState::new(
            Arc::new(Config::default()),
            Arc::new(PontifexEnclaveClient::new(0, 0)),
            Arc::new(Readiness::new()),
            Arc::new(metrics),
        );
        let app = Router::new()
            .route("/v1/things/{id}", get(|| async { "ok" }))
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                record_metrics,
            ))
            .with_state(state);

        app.oneshot(
            Request::builder()
                .uri("/v1/things/abc")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should succeed");

        let metric = {
            let lines = emitted.lock().expect("mutex should not be poisoned");
            lines
                .iter()
                .find(|line| line.contains("http.request:"))
                .expect("a request metric should have been emitted")
                .clone()
        };

        assert!(metric.contains("route:/v1/things/{id}"), "{metric}");
        assert!(metric.contains("status:200"), "{metric}");
    }
}

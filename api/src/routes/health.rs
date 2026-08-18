use axum::http::StatusCode;

/// Handles liveness probes.
///
/// Answers for the process and nothing else. It deliberately does **not** consult the
/// enclave: liveness failure means "restart me", and restarting the host cannot fix an
/// enclave that is down. That distinction is what keeps a dependency outage from becoming
/// a crash loop.
pub async fn handler() -> StatusCode {
    StatusCode::OK
}

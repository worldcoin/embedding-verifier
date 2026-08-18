use axum::{Json, extract::State, http::StatusCode};

use crate::readiness::ReadinessReport;
use crate::types::AppState;

/// Handles readiness probes.
///
/// Reads the background-maintained readiness state rather than probing the enclave inline,
/// so probe traffic cannot amplify into the enclave and a probe deadline is never a
/// function of enclave latency. The body names the unmet conditions.
pub async fn handler(State(state): State<AppState>) -> (StatusCode, Json<ReadinessReport>) {
    let report = state.readiness().report();
    let status = if report.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, Json(report))
}

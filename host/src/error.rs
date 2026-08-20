//! Universal error handling for the API.
//!
//! Every route returns [`AppError`], so status codes, response bodies and logging are decided
//! in one place. Enclave failures map differently per route, since the same enclave error
//! means different things depending on what was asked, so each route gets its own constructor
//! rather than a blanket `From` impl.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use enclave_types::EnclaveError;
use serde::Serialize;

use crate::enclave::EnclaveClientError;

/// Error envelope returned to clients.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiErrorResponse {
    /// Whether the client should retry the request.
    allow_retry: bool,
    /// Error details.
    error: ErrorBody,
}

/// Machine-readable code and human-readable message.
#[derive(Debug, Serialize)]
struct ErrorBody {
    /// Stable identifier a client can branch on.
    code: &'static str,
    /// Description for a human reading logs or a response.
    message: &'static str,
}

/// An API failure, with the status and body to return for it.
#[derive(Debug)]
pub struct AppError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    allow_retry: bool,
    /// Extra context for logs. Never serialized, since it may name internals.
    detail: Option<String>,
}

impl AppError {
    /// Creates an error with the given status and body.
    #[must_use]
    pub const fn new(
        status: StatusCode,
        code: &'static str,
        message: &'static str,
        allow_retry: bool,
    ) -> Self {
        Self {
            status,
            code,
            message,
            allow_retry,
            detail: None,
        }
    }

    /// Attaches context that is logged but not returned to the client.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// The status this error will return. Exposed for tests and callers that branch on it.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// The machine-readable code this error will return.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Maps an enclave failure on the assignment route.
    ///
    /// Match-path errors cannot arise from an attestation request, so reaching one means the
    /// enclave answered a request it was not asked. That is a host bug, not retryable
    /// unavailability.
    #[must_use]
    pub fn enclave_assignment(error: &EnclaveClientError) -> Self {
        match error {
            EnclaveClientError::Timeout | EnclaveClientError::Transport(_) => {
                Self::enclave_unreachable(error)
            }
            EnclaveClientError::Operation(operation) => match operation {
                EnclaveError::NotReady
                | EnclaveError::SecureModuleNotInitialized
                | EnclaveError::AttestationFailed => Self::enclave_not_ready(*operation),
                EnclaveError::BadRequest
                | EnclaveError::ChallengeDecryptFailed
                | EnclaveError::ImageAnalysisFailed
                | EnclaveError::Internal => Self::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Internal server error",
                    false,
                )
                .with_detail(format!(
                    "unexpected enclave error on assignment: {operation:?}"
                )),
            },
        }
    }

    /// Maps an enclave failure on the match route.
    #[must_use]
    pub fn enclave_match(error: &EnclaveClientError) -> Self {
        match error {
            EnclaveClientError::Timeout | EnclaveClientError::Transport(_) => {
                Self::enclave_unreachable(error)
            }
            EnclaveClientError::Operation(operation) => match operation {
                // The request did not open. Indistinguishable from a corrupt ciphertext here, so
                // the client is told to re-assign and re-seal -- once. See the spec's §6 note on
                // bounding this retry: an unbounded one would loop on a genuine sealing bug.
                EnclaveError::BadRequest => Self::new(
                    StatusCode::CONFLICT,
                    "reassign_required",
                    "The request was not sealed to this enclave's current encryption key",
                    true,
                )
                .with_detail(format!("{operation:?}")),
                // The one input the host supplied, so it is attributed outward rather than to the
                // caller or the enclave.
                EnclaveError::ChallengeDecryptFailed => Self::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "challenge_decrypt_failed",
                    "The challenge image could not be decrypted",
                    false,
                )
                .with_detail(format!("{operation:?}")),
                // About the photograph, not the person, so the client must see it to retake.
                EnclaveError::ImageAnalysisFailed => Self::new(
                    StatusCode::BAD_REQUEST,
                    "image_analysis_failed",
                    "An input image was rejected",
                    false,
                )
                .with_detail(format!("{operation:?}")),
                EnclaveError::Internal => Self::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Internal server error",
                    true,
                )
                .with_detail(format!("{operation:?}")),
                EnclaveError::NotReady
                | EnclaveError::SecureModuleNotInitialized
                | EnclaveError::AttestationFailed => Self::enclave_not_ready(*operation),
            },
        }
    }

    /// The request never reached a working enclave.
    fn enclave_unreachable(error: &EnclaveClientError) -> Self {
        match error {
            EnclaveClientError::Timeout => Self::new(
                StatusCode::GATEWAY_TIMEOUT,
                "enclave_timeout",
                "The enclave did not answer in time",
                true,
            ),
            EnclaveClientError::Transport(detail) => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "enclave_unreachable",
                "The enclave is unreachable",
                true,
            )
            .with_detail(detail.clone()),
            EnclaveClientError::Operation(_) => unreachable!("caller matched a transport failure"),
        }
    }

    /// The enclave answered but cannot serve requests yet.
    fn enclave_not_ready(operation: EnclaveError) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "enclave_not_ready",
            "The enclave is not ready",
            true,
        )
        .with_detail(format!("{operation:?}"))
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            tracing::error!(
                code = self.code,
                status = %self.status,
                detail = self.detail.as_deref().unwrap_or_default(),
                dependency = "enclave",
                "request failed"
            );
        } else {
            tracing::warn!(
                code = self.code,
                status = %self.status,
                detail = self.detail.as_deref().unwrap_or_default(),
                "request rejected"
            );
        }

        let body = ApiErrorResponse {
            allow_retry: self.allow_retry,
            error: ErrorBody {
                code: self.code,
                message: self.message,
            },
        };

        (self.status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use enclave_types::EnclaveError;

    use super::AppError;
    use crate::enclave::EnclaveClientError;

    #[test]
    fn assignment_maps_transport_failures_to_retryable_statuses() {
        for (error, status, code) in [
            (
                EnclaveClientError::Timeout,
                StatusCode::GATEWAY_TIMEOUT,
                "enclave_timeout",
            ),
            (
                EnclaveClientError::Transport("boom".to_string()),
                StatusCode::SERVICE_UNAVAILABLE,
                "enclave_unreachable",
            ),
        ] {
            let mapped = AppError::enclave_assignment(&error);
            assert_eq!(mapped.status(), status);
            assert_eq!(mapped.code(), code);
            assert!(mapped.allow_retry, "{code} should be retryable");
        }
    }

    #[test]
    fn both_routes_agree_that_a_not_ready_enclave_is_retryable() {
        for operation in [
            EnclaveError::NotReady,
            EnclaveError::SecureModuleNotInitialized,
            EnclaveError::AttestationFailed,
        ] {
            let error = EnclaveClientError::Operation(operation);

            for mapped in [
                AppError::enclave_assignment(&error),
                AppError::enclave_match(&error),
            ] {
                assert_eq!(mapped.status(), StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(mapped.code(), "enclave_not_ready");
                assert!(mapped.allow_retry);
            }
        }
    }

    /// The same enclave error means different things depending on what was asked, which is
    /// why the mapping is per route rather than a blanket `From` impl.
    #[test]
    fn an_unopenable_request_is_retryable_on_matches_and_a_host_bug_on_assignment() {
        let error = EnclaveClientError::Operation(EnclaveError::BadRequest);

        // On the match path the client should re-assign and re-seal.
        let mapped = AppError::enclave_match(&error);
        assert_eq!(mapped.status(), StatusCode::CONFLICT);
        assert!(mapped.allow_retry);

        // Reaching it from an attestation request means the enclave answered something it was
        // never asked, which is a host bug and not retryable.
        let mapped = AppError::enclave_assignment(&error);
        assert_eq!(mapped.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!mapped.allow_retry);
    }

    /// The challenge blob is the host's input and the image is the caller's, so neither may be
    /// reported as an enclave fault.
    #[test]
    fn match_inputs_are_attributed_to_whoever_supplied_them() {
        let mapped = AppError::enclave_match(&EnclaveClientError::Operation(
            EnclaveError::ChallengeDecryptFailed,
        ));
        assert_eq!(mapped.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(mapped.code(), "challenge_decrypt_failed");
        assert!(!mapped.allow_retry);

        let mapped = AppError::enclave_match(&EnclaveClientError::Operation(
            EnclaveError::ImageAnalysisFailed,
        ));
        assert_eq!(mapped.status(), StatusCode::BAD_REQUEST);
        assert_eq!(mapped.code(), "image_analysis_failed");
        assert!(!mapped.allow_retry);
    }
}

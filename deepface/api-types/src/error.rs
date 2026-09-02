use serde::{Deserialize, Serialize};

/// The error envelope every failing route returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiErrorResponse {
    /// Whether the client should retry the request.
    pub allow_retry: bool,
    /// Error details.
    pub error: ApiError,
}

/// Machine-readable code and human-readable message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    /// Stable identifier a client can branch on.
    pub code: String,
    /// Description for a human reading logs or a response.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::{ApiError, ApiErrorResponse};

    /// `allowRetry` is the one camelCase key in the contract, and the client branches on
    /// `error.code` to decide whether to re-assign. Both are pinned here.
    #[test]
    fn the_envelope_keeps_its_wire_names() {
        let body = ApiErrorResponse {
            allow_retry: true,
            error: ApiError {
                code: "reassign_required".to_owned(),
                message: "The request was not sealed to this enclave's current encryption key"
                    .to_owned(),
            },
        };
        let json = serde_json::json!({
            "allowRetry": true,
            "error": {
                "code": "reassign_required",
                "message": "The request was not sealed to this enclave's current encryption key",
            },
        });

        assert_eq!(serde_json::to_value(&body).expect("should serialize"), json);
        assert_eq!(
            serde_json::from_value::<ApiErrorResponse>(json).expect("should deserialize"),
            body
        );
    }
}

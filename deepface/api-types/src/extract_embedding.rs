use serde::{Deserialize, Serialize};

/// `POST /v1/extract-embedding` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractEmbeddingRequestBody {
    /// The sealed extraction request, base64.
    pub ciphertext: String,
}

/// `POST /v1/extract-embedding` response.
///
/// The embedding or failure reason is sealed for the requester. The host learns only that the
/// enclave answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractEmbeddingResponseBody {
    /// The sealed outcome, base64.
    pub response_ciphertext: String,
}

#[cfg(test)]
mod tests {
    use super::{ExtractEmbeddingRequestBody, ExtractEmbeddingResponseBody};

    #[test]
    fn the_request_keeps_its_wire_names() {
        let body = ExtractEmbeddingRequestBody {
            ciphertext: "c2VhbGVk".to_owned(),
        };
        let json = serde_json::json!({ "ciphertext": "c2VhbGVk" });

        assert_eq!(serde_json::to_value(&body).expect("should serialize"), json);
        assert_eq!(
            serde_json::from_value::<ExtractEmbeddingRequestBody>(json)
                .expect("should deserialize"),
            body
        );
    }

    #[test]
    fn the_response_keeps_its_wire_names() {
        let body = ExtractEmbeddingResponseBody {
            response_ciphertext: "c2VhbGVk".to_owned(),
        };
        let json = serde_json::json!({ "response_ciphertext": "c2VhbGVk" });

        assert_eq!(serde_json::to_value(&body).expect("should serialize"), json);
        assert_eq!(
            serde_json::from_value::<ExtractEmbeddingResponseBody>(json)
                .expect("should deserialize"),
            body
        );
    }
}

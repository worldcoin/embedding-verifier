use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::EnclaveError;

/// Requests extraction of an embedding from one image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractEmbeddingRequest {
    /// The sealed request: `enc || ciphertext`, relayed verbatim.
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}

impl Request for ExtractEmbeddingRequest {
    const ROUTE_ID: &'static str = "/v1/extract-embedding";
    type Response = Result<ExtractEmbeddingResponse, EnclaveError>;
}

/// The sealed outcome of embedding extraction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractEmbeddingResponse {
    /// The sealed payload: `response_nonce || ciphertext`, readable only by the requester.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use pontifex::Request;

    use super::ExtractEmbeddingRequest;

    #[test]
    fn extract_embedding_route_id_is_versioned_and_stable() {
        assert_eq!(ExtractEmbeddingRequest::ROUTE_ID, "/v1/extract-embedding");
    }
}

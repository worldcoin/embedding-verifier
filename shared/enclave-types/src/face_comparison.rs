use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::EnclaveError;

/// Requests an in-enclave comparison of embeddings generated from two face images.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompareFacesRequest {
    /// Encoded JPEG, PNG, or WebP reference image.
    #[serde(with = "serde_bytes")]
    pub reference_image: Vec<u8>,
    /// Encoded JPEG, PNG, or WebP probe image.
    #[serde(with = "serde_bytes")]
    pub probe_image: Vec<u8>,
}

impl Request for CompareFacesRequest {
    const ROUTE_ID: &'static str = "/v1/compare-faces";
    type Response = Result<CompareFacesResponse, EnclaveError>;
}

/// Result of comparing two embeddings generated inside the enclave.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CompareFacesResponse {
    /// Cosine similarity between the generated embeddings.
    pub similarity: f32,
    /// Whether the similarity meets the enclave's comparison threshold.
    pub matches: bool,
}

#[cfg(test)]
mod tests {
    use pontifex::Request;

    use super::{CompareFacesRequest, CompareFacesResponse};

    #[test]
    fn route_id_is_versioned_and_stable() {
        assert_eq!(CompareFacesRequest::ROUTE_ID, "/v1/compare-faces");
    }

    #[test]
    fn response_preserves_similarity_and_decision() {
        let response = CompareFacesResponse {
            similarity: 0.75,
            matches: true,
        };

        assert!((response.similarity - 0.75).abs() < f32::EPSILON);
        assert!(response.matches);
    }
}

use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::EnclaveError;

/// Requests an attestation document containing the enclave's transit public key.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetTransitKeyRequest;

impl Request for GetTransitKeyRequest {
    const ROUTE_ID: &'static str = "/v1/transit-key";
    type Response = Result<GetTransitKeyResponse, EnclaveError>;
}

/// An NSM attestation document containing the boot-scoped transit public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetTransitKeyResponse {
    /// Raw COSE-encoded Nitro attestation document.
    #[serde(with = "serde_bytes")]
    pub attestation: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use pontifex::Request;

    use super::{GetTransitKeyRequest, GetTransitKeyResponse};

    #[test]
    fn transit_key_route_id_is_versioned_and_stable() {
        assert_eq!(GetTransitKeyRequest::ROUTE_ID, "/v1/transit-key");
    }

    #[test]
    fn response_preserves_attestation_bytes() {
        let response = GetTransitKeyResponse {
            attestation: vec![1, 2, 3],
        };

        assert_eq!(response.attestation, vec![1, 2, 3]);
    }
}

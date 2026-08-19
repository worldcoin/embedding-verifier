use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::EnclaveError;

/// Requests attestation documents for the enclave's boot-scoped public keys.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetEnclaveKeysRequest;

impl Request for GetEnclaveKeysRequest {
    const ROUTE_ID: &'static str = "/v1/enclave-keys";
    type Response = Result<GetEnclaveKeysResponse, EnclaveError>;
}

/// One NSM attestation document per boot-scoped public key.
///
/// Each key gets its own document because an attestation carries a single
/// `public_key` field. Both documents are public and relay unsealed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetEnclaveKeysResponse {
    /// Raw COSE-encoded document attesting the encryption public key.
    #[serde(with = "serde_bytes")]
    pub encryption_key_attestation: Vec<u8>,
    /// Raw COSE-encoded document attesting the `BabyJubJub` `EdDSA` public key.
    #[serde(with = "serde_bytes")]
    pub signing_key_attestation: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use pontifex::Request;

    use super::{GetEnclaveKeysRequest, GetEnclaveKeysResponse};

    #[test]
    fn enclave_keys_route_id_is_versioned_and_stable() {
        assert_eq!(GetEnclaveKeysRequest::ROUTE_ID, "/v1/enclave-keys");
    }

    #[test]
    fn response_preserves_both_attestations() {
        let response = GetEnclaveKeysResponse {
            encryption_key_attestation: vec![1, 2, 3],
            signing_key_attestation: vec![4, 5, 6],
        };

        assert_eq!(response.encryption_key_attestation, vec![1, 2, 3]);
        assert_eq!(response.signing_key_attestation, vec![4, 5, 6]);
    }
}

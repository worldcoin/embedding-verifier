use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::EnclaveError;

/// Binds a credential image to the `thumbnail.png` hash committed in its PCP
/// `hashes.json`, returning `credential_claim = SHA256(hashes.json)`.
///
/// `sealed_payload` is a libsodium sealed box (anonymous X25519) encrypted to the
/// enclave's boot-scoped transit public key (see [`crate::GetTransitKeyRequest`]).
/// Its plaintext framing is owned by the enclave.
///
/// This operation performs **no** orb-attestation signature verification and makes
/// **no** provenance claim: it checks internal consistency only (image matches the
/// self-declared `hashes.json` commitment). The returned `credential_claim` is a
/// commitment, not a proof of genuine enrollment — anti-forgery is enforced
/// downstream by the ZK circuit, not here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindPcpRequest {
    /// Sealed-box ciphertext addressed to the enclave transit public key.
    #[serde(with = "serde_bytes")]
    pub sealed_payload: Vec<u8>,
}

impl Request for BindPcpRequest {
    const ROUTE_ID: &'static str = "/v1/pcp-binding";
    type Response = Result<BindPcpResponse, EnclaveError>;
}

/// Result of a successful PCP binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindPcpResponse {
    /// `credential_claim = SHA256(hashes.json raw bytes)`.
    ///
    /// A commitment to the PCP the credential image was bound to — **not** a proof
    /// of genuine enrollment. It is meaningful only once a downstream ZK circuit
    /// binds it to an issuer-signed, registry-included credential.
    pub credential_claim: [u8; 32],
}

#[cfg(test)]
mod tests {
    use pontifex::Request;

    use super::{BindPcpRequest, BindPcpResponse};

    #[test]
    fn pcp_binding_route_id_is_versioned_and_stable() {
        assert_eq!(BindPcpRequest::ROUTE_ID, "/v1/pcp-binding");
    }

    #[test]
    fn response_preserves_credential_claim() {
        let response = BindPcpResponse {
            credential_claim: [7u8; 32],
        };

        assert_eq!(response.credential_claim, [7u8; 32]);
    }
}

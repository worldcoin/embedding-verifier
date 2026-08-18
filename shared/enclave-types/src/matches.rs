use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::EnclaveError;

/// Requests a 3-way face match.
///
/// `sealed_payload` is an anonymous X25519 sealed box, encrypted to the enclave's
/// transit public key, wrapping the CBOR-framed match inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchRequest {
    /// Sealed-box ciphertext addressed to the enclave transit public key.
    #[serde(with = "serde_bytes")]
    pub sealed_payload: Vec<u8>,
}

impl Request for MatchRequest {
    const ROUTE_ID: &'static str = "/v1/matches";
    type Response = Result<MatchResponse, EnclaveError>;
}

/// The match statement and its enclave signature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchResponse {
    /// The claims the enclave attests to.
    pub statement: MatchStatement,
    /// Signature over `statement`. **Placeholder** until output signing lands.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// The claims a match statement commits to — the TEE-output CWT claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchStatement {
    /// Statement format version.
    pub version: u8,
    /// SHA256 of the live image.
    pub live_image_hash: [u8; 32],
    /// PCP commitment `SHA256(hashes.json)`; a commitment, not a proof of enrollment.
    /// The `DeepFace` circuit binds it to the credential's `claims`, which is what makes
    /// the in-enclave image-to-`hashes.json` binding meaningful.
    pub credential_claim: [u8; 32],
    /// SHA256 of the challenge image.
    pub challenger_image_hash: [u8; 32],
    /// Credential-vs-live similarity score. **Dummy** until the face engine lands.
    pub match_coefficient: f32,
}

#[cfg(test)]
mod tests {
    use pontifex::Request;

    use super::MatchRequest;

    #[test]
    fn matches_route_id_is_versioned_and_stable() {
        assert_eq!(MatchRequest::ROUTE_ID, "/v1/matches");
    }
}

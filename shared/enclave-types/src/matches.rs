use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::EnclaveError;

/// Requests a 3-way face match.
///
/// `sealed_payload` is a an anonymous X25519 sealed box encrypted to the enclave's transit public key.
/// Its plaintext is the CBOR-framed match inputs:
/// - credential image
/// - PCP `hashes.json`
/// - live image
/// - challenge image
/// - match threshold
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchRequest {
    /// Sealed-box ciphertext addressed to the enclave transit public key. Its
    /// plaintext is the CBOR-framed match inputs.
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

/// The claims a match statement commits to.
///
/// Mirrors the TEE-output CWT claims in the protocol design: the enclave
/// commits to the hashes of the images it compared plus the resulting coefficient,
/// and the downstream circuit re-binds each hash to its attested source (AAT signal,
/// credential claims, RP-supplied challenge hash). Common WDP83 claims not yet
/// populated (model bundle, enclave PCR measurement, timestamp) are intentionally
/// omitted until the corresponding features exist.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchStatement {
    /// Statement format version.
    pub version: u8,
    /// SHA256 of the live image. The circuit binds this to the AAT `signal`.
    pub live_image_hash: [u8; 32],
    /// Commitment to the PCP: `SHA256(hashes.json)`. Binds the compared credential
    /// image to the credential the circuit validates. A commitment, not a proof of
    /// genuine Orb enrollment (see [`MatchRequest`]).
    pub credential_claim: [u8; 32],
    /// SHA256 of the challenge image. The RP verifies this against the challenge it
    /// supplied as a public circuit input.
    pub challenger_image_hash: [u8; 32],
    /// Similarity score of the credential-vs-live comparison. The circuit re-checks
    /// `match_coefficient >= match_threshold`. **Dummy** until the face engine is
    /// integrated. The credential-vs-challenge comparison is enforced inside the
    /// enclave and vouched for by the issuance of this statement.
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

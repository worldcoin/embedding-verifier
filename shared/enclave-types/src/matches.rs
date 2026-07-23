use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::EnclaveError;

/// Face-match mode. Only 2-way (liveness vs. PCP credential image) is implemented
/// in this skeleton; 3-way and chained modes are future work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchMode {
    /// Liveness image compared against the PCP credential image.
    TwoWay,
}

/// Requests a face match.
///
/// `sealed_payload` is a libsodium sealed box (anonymous X25519) encrypted to the
/// enclave's boot-scoped transit public key (see [`crate::GetTransitKeyRequest`]).
/// Its plaintext is the CBOR-framed match inputs (liveness image, credential image,
/// PCP `hashes.json`) — framing owned by the enclave.
///
/// The enclave verifies internal PCP consistency (image binds to the self-declared
/// `hashes.json` commitment) but performs **no** orb-attestation signature
/// verification and makes no provenance claim on the inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchRequest {
    /// Sealed-box ciphertext addressed to the enclave transit public key.
    #[serde(with = "serde_bytes")]
    pub sealed_payload: Vec<u8>,
    /// Opaque caller/subject binding (e.g. wallet address / signal), echoed into the
    /// statement so the consumer can bind the match to a subject.
    #[serde(with = "serde_bytes")]
    pub subject_binding: Vec<u8>,
    /// Minimum similarity the caller requires. Convenience gate only; the real
    /// guarantee is intended to come from in-circuit verification downstream.
    pub similarity_threshold: f32,
}

impl Request for MatchRequest {
    const ROUTE_ID: &'static str = "/v1/matches";
    type Response = Result<MatchResponse, EnclaveError>;
}

/// A match statement plus its signature.
///
/// SKELETON: `signature` is a placeholder (all-zero) and
/// [`MatchStatement::match_coefficient`] is a dummy value. The face comparison and
/// statement signing are not yet implemented, so this response is **not** usable for
/// real verification.
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
/// Common WDP83 claims not yet populated (model bundle, enclave PCR measurement,
/// timestamp, integrity root of trust) are intentionally omitted until the
/// corresponding features exist.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchStatement {
    /// Statement format version.
    pub version: u8,
    /// The mode that produced this statement.
    pub mode: MatchMode,
    /// Opaque caller/subject binding, echoed from the request.
    #[serde(with = "serde_bytes")]
    pub subject_binding: Vec<u8>,
    /// SHA256 of the PCP credential image that was matched.
    pub pcp_thumbnail_hash: [u8; 32],
    /// SHA256 of the liveness image.
    pub live_image_hash: [u8; 32],
    /// Commitment to the PCP: `SHA256(hashes.json)`. A commitment, not a proof of
    /// genuine enrollment (see [`MatchRequest`]).
    pub credential_claim: [u8; 32],
    /// Similarity score. **Dummy** until the face engine is integrated.
    pub match_coefficient: f32,
    /// Minimum similarity requested by the caller.
    pub similarity_threshold: f32,
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

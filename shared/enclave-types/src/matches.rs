use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::EnclaveError;

/// Requests a 3-way face match.
///
/// The entire set of match inputs — credential image, PCP `hashes.json`, live image,
/// challenge image, and the RP-supplied match threshold — is CBOR-framed (framing
/// owned by the enclave) and encrypted into `sealed_payload` as a libsodium sealed
/// box (anonymous X25519) addressed to the enclave's boot-scoped transit public key
/// (see [`crate::GetTransitKeyRequest`]). Nothing travels in the clear: the doc
/// requires the whole payload to be encrypted to the TEE.
///
/// The enclave verifies internal PCP consistency (the credential image binds to the
/// self-declared `hashes.json` commitment) but performs **no** orb-attestation
/// signature verification and makes no provenance claim on the inputs. Provenance is
/// re-anchored downstream in the Deep Face Proof Circuit.
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

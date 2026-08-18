use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::EnclaveError;

/// Requests a 3-way face match.
///
/// `sealed_payload` wraps the CBOR-framed match inputs under HPKE (RFC 9180)
/// `mode_base`, sealed to the enclave's boot-scoped encryption public key. See
/// the `sealing` module for the ciphersuite and the `enc || ciphertext` framing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchRequest {
    /// HPKE-sealed payload addressed to the enclave encryption public key.
    #[serde(with = "serde_bytes")]
    pub sealed_payload: Vec<u8>,
}

impl Request for MatchRequest {
    const ROUTE_ID: &'static str = "/v1/matches";
    type Response = Result<MatchResponse, EnclaveError>;
}

/// The sealed match outcome.
///
/// Opaque to the host, which relays it unread: the statement commits to biometric-derived
/// values, and the host is outside the trust boundary. Sealed under the response key both
/// sides derive from the request's HPKE context, so it needs no client-held keypair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchResponse {
    /// AES-128-GCM ciphertext wrapping the CBOR-framed [`MatchOutcome`].
    #[serde(with = "serde_bytes")]
    pub sealed_outcome: Vec<u8>,
}

/// The plaintext the enclave seals into a [`MatchResponse`].
///
/// Enclave-and-client only. The host never holds the key that opens it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchOutcome {
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
    pub credential_claim: [u8; 32],
    /// SHA256 of the challenge image.
    pub challenger_image_hash: [u8; 32],
    /// Credential-vs-live similarity score.
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

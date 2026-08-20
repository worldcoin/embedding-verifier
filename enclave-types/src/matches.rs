use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::EnclaveError;

/// Requests a 3-way face match. Both fields are ciphertext the host cannot read;
/// `challenge_ciphertext` is keyed from inside `body`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchRequest {
    /// The sealed request: `enc || ciphertext`, relayed verbatim.
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    /// The RP's challenge image, AES-256-GCM ciphertext fetched by the host.
    #[serde(with = "serde_bytes")]
    pub challenge_ciphertext: Vec<u8>,
}

impl Request for MatchRequest {
    const ROUTE_ID: &'static str = "/v1/matches";
    type Response = Result<MatchResponse, EnclaveError>;
}

/// The sealed outcome of a match.
///
/// `outcome` is cleartext so the host can pick a status code. It is a hint, not the authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchResponse {
    /// Coarse outcome class, readable by the host.
    pub outcome: MatchOutcome,
    /// The sealed payload: `response_nonce || ciphertext`, readable only by the requester.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

/// Coarse, cleartext class of a [`MatchResponse`]. The detail stays sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchOutcome {
    /// The match held; the sealed payload carries a signed statement.
    Statement,
    /// The match did not hold; the sealed payload carries the reason.
    Rejected,
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

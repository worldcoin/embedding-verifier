use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::EnclaveError;

/// Version of the match channel's wire contract.
///
/// Bound into the HPKE `info` (see [`channel_info`]) and repeated inside the sealed
/// request plaintext, so a version change fails at channel setup rather than as a
/// misparse.
pub const CHANNEL_VERSION: u8 = 1;

/// Domain-separation prefix for the match channel's HPKE `info`.
const CHANNEL_INFO_DOMAIN: &[u8] = b"embedding-verifier/match";

/// Length of an HPKE encapsulated key under DHKEM(X25519, HKDF-SHA256) — RFC 9180 §7.1.
pub const ENCAPPED_KEY_LEN: usize = 32;

/// Exporter context for the response key — RFC 9180 §9.8.
pub const RESPONSE_KEY_LABEL: &[u8] = b"response key";

/// Exporter context for the response nonce — RFC 9180 §9.8.
pub const RESPONSE_NONCE_LABEL: &[u8] = b"response nonce";

/// ChaCha20-Poly1305 key length (RFC 9180 `Nk`).
pub const RESPONSE_KEY_LEN: usize = 32;

/// ChaCha20-Poly1305 nonce length (RFC 9180 `Nn`).
pub const RESPONSE_NONCE_LEN: usize = 12;

/// Poly1305 authentication tag length, appended to every AEAD ciphertext.
pub const AEAD_TAG_LEN: usize = 16;

/// Builds the HPKE `info` both parties bind into the key schedule.
///
/// Binding `transit_public_key` means a client that sealed to a *different* enclave boot
/// cannot open a channel at all; binding `version` means a wire-format change fails at
/// setup rather than producing a garbled plaintext.
#[must_use]
pub fn channel_info(version: u8, transit_public_key: &[u8; 32]) -> Vec<u8> {
    let mut info = Vec::with_capacity(CHANNEL_INFO_DOMAIN.len() + 1 + transit_public_key.len());
    info.extend_from_slice(CHANNEL_INFO_DOMAIN);
    info.push(version);
    info.extend_from_slice(transit_public_key);
    info
}

/// Requests a 3-way face match over an HPKE channel (RFC 9180 base mode).
///
/// The client runs `SetupBaseS` against the enclave's attested transit public key and
/// seals the CBOR-framed match inputs. The host relays both fields opaquely: it can
/// neither read the request nor tamper with it undetected, and it holds no key that
/// would let it open the response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchRequest {
    /// HPKE encapsulated key (`enc`), [`ENCAPPED_KEY_LEN`] bytes.
    #[serde(with = "serde_bytes")]
    pub enc: Vec<u8>,
    /// HPKE ciphertext over the CBOR-framed match inputs.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

impl Request for MatchRequest {
    const ROUTE_ID: &'static str = "/v1/matches";
    type Response = Result<MatchResponse, EnclaveError>;
}

/// The sealed outcome of a match, encrypted to the requesting client.
///
/// The response key and nonce are exported from the *same* HPKE context the request
/// arrived on (RFC 9180 §9.8), so only the holder of that request's ephemeral secret can
/// open it. Because the context is bound to the attested `transit_pk`, opening the
/// response also authenticates its origin — that property lands here, ahead of statement
/// signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchResponse {
    /// Coarse outcome class, in the clear so the host can pick a status code and count
    /// failures without learning why a face failed.
    ///
    /// Integrity-protected, not confidential: it is bound into the response AAD (see
    /// [`MatchOutcome::response_aad`]), so a host that flips it makes `ciphertext` fail
    /// to open. Clients must still treat the sealed [`MatchOutcomePayload`] as the
    /// authoritative outcome.
    pub outcome: MatchOutcome,
    /// ChaCha20-Poly1305 ciphertext over the CBOR-framed [`MatchOutcomePayload`].
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

/// The authoritative, sealed outcome of a match.
pub type MatchOutcomePayload = Result<MatchStatement, RejectReason>;

/// Coarse, cleartext class of a [`MatchResponse`]. The detail stays sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchOutcome {
    /// The match held; the sealed payload is `Ok(MatchStatement)`.
    Statement,
    /// The match did not hold; the sealed payload is `Err(RejectReason)`.
    Rejected,
}

impl MatchOutcome {
    /// Stable one-byte encoding, bound into the response AAD.
    ///
    /// Both sides derive the AAD from the class they believe applies, so a host that
    /// rewrites [`MatchResponse::outcome`] turns the response into an authentication
    /// failure instead of a silent downgrade.
    #[must_use]
    pub const fn response_aad(self) -> [u8; 1] {
        match self {
            Self::Statement => [0x01],
            Self::Rejected => [0x02],
        }
    }
}

/// Why a well-formed match request did not yield a statement.
///
/// These say *why a face failed* and are therefore only ever sent sealed — the host sees
/// [`MatchOutcome::Rejected`] and nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectReason {
    /// The credential image did not match the committed `thumbnail.png` hash.
    ThumbnailHashMismatch,
    /// A comparison scored below the RP-supplied `match_threshold`.
    MatchBelowThreshold,
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
    /// Credential-vs-live similarity score. **Dummy** until the face engine lands.
    pub match_coefficient: f32,
}

#[cfg(test)]
mod tests {
    use pontifex::Request;

    use super::{CHANNEL_INFO_DOMAIN, CHANNEL_VERSION, MatchOutcome, MatchRequest, channel_info};

    #[test]
    fn matches_route_id_is_versioned_and_stable() {
        assert_eq!(MatchRequest::ROUTE_ID, "/v1/matches");
    }

    #[test]
    fn channel_info_binds_domain_version_and_transit_key() {
        let transit_public_key = [7u8; 32];

        let info = channel_info(CHANNEL_VERSION, &transit_public_key);

        let (domain, rest) = info.split_at(CHANNEL_INFO_DOMAIN.len());
        assert_eq!(domain, CHANNEL_INFO_DOMAIN);
        assert_eq!(
            rest,
            [&[CHANNEL_VERSION][..], &transit_public_key[..]].concat()
        );
    }

    #[test]
    fn channel_info_separates_versions_and_keys() {
        let key = [7u8; 32];

        assert_ne!(channel_info(1, &key), channel_info(2, &key));
        assert_ne!(channel_info(1, &key), channel_info(1, &[8u8; 32]));
    }

    #[test]
    fn outcome_classes_have_distinct_aad() {
        assert_ne!(
            MatchOutcome::Statement.response_aad(),
            MatchOutcome::Rejected.response_aad()
        );
    }
}

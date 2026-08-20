//! What travels *inside* the sealed channel on the match path.
//!
//! These types are the plaintexts, so only the requester and the enclave ever see them. The host
//! relays the ciphertext that carries them and holds no key for it.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// AES-256-GCM key length for the challenge image.
pub const CHALLENGE_KEY_LEN: usize = 32;

/// AES-256-GCM nonce length for the challenge image.
///
/// The RP stores key and IV separately, so both have to travel sealed; the spec's payload listing
/// names only the key.
pub const CHALLENGE_IV_LEN: usize = 12;

/// Why a payload could not be encoded or decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadError {
    /// The bytes were not the CBOR framing this module writes.
    Malformed,
    /// The payload declared a channel version this build does not implement.
    UnsupportedVersion,
    /// Encoding failed, which for an in-memory value should not happen.
    Encoding,
}

/// The sealed inputs to one match.
///
/// The challenge image is *not* here: the host fetches its ciphertext from the RP's bucket, and
/// only the key and IV travel sealed. That keeps the image off the mobile network and its
/// plaintext off the device, while leaving the host holding a blob it cannot read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchInputs {
    /// Channel version the requester believes it is speaking.
    ///
    /// The authoritative gate is the HPKE `info`, which binds the same value, so a requester on
    /// another version cannot open a channel at all. This field only catches one that is
    /// internally inconsistent, and makes that legible in the enclave log rather than
    /// indistinguishable from a corrupt payload.
    pub version: u8,
    /// Raw liveness image bytes.
    #[serde(with = "serde_bytes")]
    pub live_image: Vec<u8>,
    /// Raw credential image bytes (the Orb PCP thumbnail).
    #[serde(with = "serde_bytes")]
    pub credential_image: Vec<u8>,
    /// Raw `hashes.json` bytes from the PCP.
    #[serde(with = "serde_bytes")]
    pub hashes_json: Vec<u8>,
    /// Key the RP encrypted the challenge image under.
    pub challenge_image_key: [u8; CHALLENGE_KEY_LEN],
    /// IV the RP encrypted the challenge image under.
    pub challenge_image_iv: [u8; CHALLENGE_IV_LEN],
    /// Minimum similarity the RP requires. A convenience gate: the real guarantee is the
    /// in-circuit threshold check, which this cannot substitute for.
    pub match_threshold: f32,
}

impl MatchInputs {
    /// Encodes the inputs as CBOR.
    ///
    /// The result is [`Zeroizing`] because it holds raw biometric images and the challenge key.
    ///
    /// # Errors
    ///
    /// Returns [`PayloadError::Encoding`] if CBOR encoding fails.
    pub fn to_cbor(&self) -> Result<Zeroizing<Vec<u8>>, PayloadError> {
        let mut encoded = Vec::new();
        ciborium::into_writer(self, &mut encoded).map_err(|_| PayloadError::Encoding)?;

        Ok(Zeroizing::new(encoded))
    }

    /// Decodes the inputs and checks the declared version.
    ///
    /// # Errors
    ///
    /// Returns [`PayloadError::Malformed`] if the bytes are not this framing, or
    /// [`PayloadError::UnsupportedVersion`] if the declared version is not
    /// [`crate::sealed_channel::CHANNEL_VERSION`].
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, PayloadError> {
        let inputs: Self = ciborium::from_reader(bytes).map_err(|_| PayloadError::Malformed)?;

        if inputs.version == crate::sealed_channel::CHANNEL_VERSION {
            Ok(inputs)
        } else {
            Err(PayloadError::UnsupportedVersion)
        }
    }
}

/// The authoritative outcome of a match, as it travels back sealed.
///
/// `Ok` carries the serialized `COSE_Sign1` statement; `Err` says why no statement was issued.
/// The cleartext `MatchOutcome` beside the ciphertext is only a hint for the host — a requester
/// compares the two and treats a mismatch as host misbehaviour.
pub type MatchOutcomePayload = Result<Vec<u8>, RejectReason>;

/// Why a well-formed match request did not yield a statement.
///
/// These say *why a face failed*, so they are only ever sent sealed. The host sees the coarse
/// class and nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectReason {
    /// The credential image did not match the `thumbnail.png` hash committed in `hashes.json`.
    ThumbnailHashMismatch,
    /// A comparison scored below the RP-supplied `match_threshold`.
    MatchBelowThreshold,
}

/// Encodes a sealed outcome as CBOR.
///
/// # Errors
///
/// Returns [`PayloadError::Encoding`] if CBOR encoding fails.
pub fn encode_outcome(outcome: &MatchOutcomePayload) -> Result<Vec<u8>, PayloadError> {
    let mut encoded = Vec::new();
    ciborium::into_writer(outcome, &mut encoded).map_err(|_| PayloadError::Encoding)?;

    Ok(encoded)
}

/// Decodes a sealed outcome.
///
/// # Errors
///
/// Returns [`PayloadError::Malformed`] if the bytes are not this framing.
pub fn decode_outcome(bytes: &[u8]) -> Result<MatchOutcomePayload, PayloadError> {
    ciborium::from_reader(bytes).map_err(|_| PayloadError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::{
        CHALLENGE_IV_LEN, CHALLENGE_KEY_LEN, MatchInputs, MatchOutcomePayload, PayloadError,
        RejectReason, decode_outcome, encode_outcome,
    };
    use crate::sealed_channel::CHANNEL_VERSION;

    fn inputs() -> MatchInputs {
        MatchInputs {
            version: CHANNEL_VERSION,
            live_image: b"liveness-frame".to_vec(),
            credential_image: b"credential-thumbnail".to_vec(),
            hashes_json: br#"{"thumbnail.png":"aa"}"#.to_vec(),
            challenge_image_key: [7u8; CHALLENGE_KEY_LEN],
            challenge_image_iv: [9u8; CHALLENGE_IV_LEN],
            match_threshold: 0.5,
        }
    }

    #[test]
    fn inputs_round_trip() {
        let encoded = inputs().to_cbor().expect("encoding should succeed");

        let decoded = MatchInputs::from_cbor(&encoded).expect("decoding should succeed");

        assert_eq!(decoded.live_image, inputs().live_image);
        assert_eq!(decoded.credential_image, inputs().credential_image);
        assert_eq!(decoded.hashes_json, inputs().hashes_json);
        assert_eq!(decoded.challenge_image_key, inputs().challenge_image_key);
        assert_eq!(decoded.challenge_image_iv, inputs().challenge_image_iv);
        assert_eq!(
            decoded.match_threshold.to_bits(),
            inputs().match_threshold.to_bits()
        );
    }

    #[test]
    fn rejects_non_cbor_framing() {
        assert_eq!(
            MatchInputs::from_cbor(b"not cbor framing").err(),
            Some(PayloadError::Malformed)
        );
    }

    #[test]
    fn rejects_an_unsupported_version() {
        let mut inputs = inputs();
        inputs.version = CHANNEL_VERSION + 1;
        let encoded = inputs.to_cbor().expect("encoding should succeed");

        assert_eq!(
            MatchInputs::from_cbor(&encoded).err(),
            Some(PayloadError::UnsupportedVersion)
        );
    }

    #[test]
    fn outcomes_round_trip_both_arms() {
        let statement: MatchOutcomePayload = Ok(b"cose-sign1-bytes".to_vec());
        let rejection: MatchOutcomePayload = Err(RejectReason::MatchBelowThreshold);

        for outcome in [statement, rejection] {
            let encoded = encode_outcome(&outcome).expect("encoding should succeed");

            assert_eq!(
                decode_outcome(&encoded).expect("decoding should succeed"),
                outcome
            );
        }
    }

    #[test]
    fn reject_reasons_are_distinct() {
        assert_ne!(
            encode_outcome(&Err(RejectReason::ThumbnailHashMismatch)).expect("encode"),
            encode_outcome(&Err(RejectReason::MatchBelowThreshold)).expect("encode")
        );
    }
}

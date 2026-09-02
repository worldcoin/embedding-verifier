//! The two ends of one match exchange: what the requester seals in, and what the enclave seals
//! back. The host relays the ciphertext carrying both and holds no key for either.

use aes_gcm::{
    Aes256Gcm, Key, KeyInit,
    aead::{Aead, Nonce},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::match_token::MatchToken;

/// AES-256-GCM key length for the challenge image.
pub const CHALLENGE_KEY_LEN: usize = 32;

/// AES-256-GCM nonce length for the challenge image.
pub const CHALLENGE_IV_LEN: usize = 12;

/// Encrypts a challenge image. Called by the RP/`DeepFace` backend.
///
/// The caller must never reuse a `(key, iv)` pair. AES-GCM is catastrophic under nonce reuse: two
/// messages under the same pair leak their XOR and expose the authentication key, which permits tag
/// forgery.
///
/// # Errors
///
/// Returns [`Error::ChallengeDecryptFailed`] if the AEAD refuses to seal, which for an in-memory
/// plaintext should not happen.
pub fn encrypt_challenge(
    plaintext: &[u8],
    key: &[u8; CHALLENGE_KEY_LEN],
    iv: &[u8; CHALLENGE_IV_LEN],
) -> Result<Vec<u8>, Error> {
    Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key))
        .encrypt(&Nonce::<Aes256Gcm>::from(*iv), plaintext)
        .map_err(|_| Error::ChallengeDecryptFailed)
}

/// Decrypts a challenge image with the key and IV that arrived sealed.
///
/// # Errors
///
/// Returns [`Error::ChallengeDecryptFailed`] if the blob does not authenticate. A wrong key, a
/// truncated tag, and a blob substituted by the host are indistinguishable here, and none of them
/// is a face failing.
pub fn decrypt_challenge(
    ciphertext: &[u8],
    key: &[u8; CHALLENGE_KEY_LEN],
    iv: &[u8; CHALLENGE_IV_LEN],
) -> Result<Vec<u8>, Error> {
    Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key))
        .decrypt(&Nonce::<Aes256Gcm>::from(*iv), ciphertext)
        .map_err(|_| Error::ChallengeDecryptFailed)
}

/// The sealed inputs to one match.
///
/// The challenge image is not here: the host fetches its ciphertext, and only the key and IV
/// travel sealed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchInputs {
    /// Channel version the requester believes it is speaking. Advisory: the HPKE `info` binds the
    /// same value, so a mismatched requester cannot open a channel at all.
    pub version: u8,
    /// Raw liveness image bytes.
    #[serde(with = "serde_bytes")]
    pub live_image: Vec<u8>,
    /// Raw credential image bytes (the Orb PCP thumbnail).
    #[serde(with = "serde_bytes")]
    pub credential_image: Vec<u8>,
    /// The second liveness frame `LightGuard` analyses, if the requester captured one.
    ///
    /// Absent selects vanilla mode — the credential-against-live-and-challenge flow, unchanged.
    /// Present selects the `LightGuard` flow, which the enclave does not implement yet.
    ///
    /// Additive on purpose. [`Self::version`] is deliberately *not* bumped: the field defaults to
    /// absent, so a requester built before it existed still decodes, and a bump would strand every
    /// such requester over an input none of them send.
    #[serde(default, with = "serde_bytes")]
    pub light_guard_image: Option<Vec<u8>>,
    /// Raw `hashes.json` bytes from the PCP.
    #[serde(with = "serde_bytes")]
    pub hashes_json: Vec<u8>,
    /// Key the RP encrypted the challenge image under.
    pub challenge_image_key: [u8; CHALLENGE_KEY_LEN],
    /// IV the RP encrypted the challenge image under.
    pub challenge_image_iv: [u8; CHALLENGE_IV_LEN],
    /// Minimum similarity the RP requires.
    pub match_threshold: f32,
}

impl MatchInputs {
    /// Encodes the inputs as CBOR. [`Zeroizing`] because it holds biometric images and the
    /// challenge key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encoding`] if CBOR encoding fails.
    pub fn to_cbor(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut encoded = Vec::new();
        ciborium::into_writer(self, &mut encoded).map_err(|_| Error::Encoding)?;

        Ok(Zeroizing::new(encoded))
    }

    /// Decodes the inputs and checks the declared version.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] if the bytes are not this framing, or
    /// [`Error::UnsupportedChannelVersion`] if the declared version is not
    /// [`attested_channel::channel::CHANNEL_VERSION`].
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let inputs: Self = ciborium::from_reader(bytes).map_err(|_| Error::Malformed)?;

        if inputs.version == attested_channel::channel::CHANNEL_VERSION {
            Ok(inputs)
        } else {
            Err(Error::UnsupportedChannelVersion)
        }
    }
}

/// The authoritative result of a match.
///
/// Everything the enclave learns after opening the request travels in here rather than in the error
/// it returns to the host. Once a request has been opened there is a channel to answer on, so
/// surfacing any of it in the clear would tell the host about a plaintext it cannot read.
///
/// [`Self::Failed`] spans both a correct negative answer and unusable input: a match that scored
/// below the threshold failed in the same sense that a malformed payload did — no statement was
/// issued. It is *not* a transport error, and a client must not treat it as one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchResult {
    /// The match held; carries the signed statement.
    Success(MatchToken),
    /// No statement was issued; carries why.
    Failed(FailureReason),
}

impl MatchResult {
    /// Encodes the result as CBOR.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encoding`] if CBOR encoding fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut encoded = Vec::new();
        ciborium::into_writer(self, &mut encoded).map_err(|_| Error::Encoding)?;

        Ok(encoded)
    }

    /// Decodes a result.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] if the bytes are not this framing.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes).map_err(|_| Error::Malformed)
    }
}

/// Why no statement was issued.
///
/// Each of these is a fact about the sealed plaintext — either what it contained or what the
/// analysis made of it — so naming any of them in the clear would describe content the host cannot
/// read. They travel sealed without exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureReason {
    /// The plaintext was not the CBOR framing [`MatchInputs`] writes.
    MalformedInputs,
    /// The inputs declared a channel version the enclave does not implement.
    UnsupportedVersion,
    /// `hashes.json` was absent, not JSON, or missing a usable `thumbnail.png` entry.
    InvalidHashesJson,
    /// The credential image did not match the `thumbnail.png` hash committed in `hashes.json`.
    ThumbnailHashMismatch,
    /// A comparison scored below the RP-supplied `match_threshold`.
    MatchBelowThreshold,
    /// The enclave could not get from the images to a score. Covers a decode failure, a quality
    /// rejection, and a matcher that failed on well-formed embeddings; the enclave log distinguishes
    /// them.
    ImageAnalysisFailed,
    /// The challenge blob did not authenticate under the key and IV that arrived sealed.
    ///
    /// Sealed like the rest: it says the key inside *this* payload disagrees with the object the
    /// host fetched, which is a fact about the plaintext. A client that sealed the wrong key and an
    /// RP serving a stale object are indistinguishable from here.
    ChallengeDecryptFailed,
}

#[cfg(test)]
mod tests {
    use attested_channel::channel::CHANNEL_VERSION;

    use super::{
        CHALLENGE_IV_LEN, CHALLENGE_KEY_LEN, Error, FailureReason, MatchInputs, MatchResult,
        decrypt_challenge, encrypt_challenge,
    };

    use crate::match_token::MatchToken;

    /// Fresh per call: no test needs a fixed nonce, and a literal IV in the tree is both a scanner
    /// finding and a bad example to copy.
    fn key_and_iv() -> ([u8; CHALLENGE_KEY_LEN], [u8; CHALLENGE_IV_LEN]) {
        (rand::random(), rand::random())
    }

    fn inputs() -> MatchInputs {
        MatchInputs {
            version: CHANNEL_VERSION,
            live_image: b"liveness-frame".to_vec(),
            credential_image: b"credential-thumbnail".to_vec(),
            light_guard_image: None,
            hashes_json: br#"{"thumbnail.png":"aa"}"#.to_vec(),
            challenge_image_key: [7u8; CHALLENGE_KEY_LEN],
            challenge_image_iv: [9u8; CHALLENGE_IV_LEN],
            match_threshold: 0.5,
        }
    }

    /// `MatchInputs` as it was framed before `light_guard_image` existed. Encoding through this is
    /// the only way to produce the payload a requester built against the old struct actually sends.
    #[derive(serde::Serialize)]
    struct PreLightGuardInputs {
        version: u8,
        #[serde(with = "serde_bytes")]
        live_image: Vec<u8>,
        #[serde(with = "serde_bytes")]
        credential_image: Vec<u8>,
        #[serde(with = "serde_bytes")]
        hashes_json: Vec<u8>,
        challenge_image_key: [u8; CHALLENGE_KEY_LEN],
        challenge_image_iv: [u8; CHALLENGE_IV_LEN],
        match_threshold: f32,
    }

    #[test]
    fn inputs_round_trip() {
        let encoded = inputs().to_cbor().expect("encoding should succeed");

        let decoded = MatchInputs::from_cbor(&encoded).expect("decoding should succeed");

        assert_eq!(decoded.live_image, inputs().live_image);
        assert_eq!(decoded.credential_image, inputs().credential_image);
        assert_eq!(decoded.light_guard_image, inputs().light_guard_image);
        assert_eq!(decoded.hashes_json, inputs().hashes_json);
        assert_eq!(decoded.challenge_image_key, inputs().challenge_image_key);
        assert_eq!(decoded.challenge_image_iv, inputs().challenge_image_iv);
        assert_eq!(
            decoded.match_threshold.to_bits(),
            inputs().match_threshold.to_bits()
        );
    }

    #[test]
    fn a_light_guard_image_round_trips() {
        let mut inputs = inputs();
        inputs.light_guard_image = Some(b"second-liveness-frame".to_vec());
        let encoded = inputs.to_cbor().expect("encoding should succeed");

        let decoded = MatchInputs::from_cbor(&encoded).expect("decoding should succeed");

        assert_eq!(
            decoded.light_guard_image.as_deref(),
            Some(&b"second-liveness-frame"[..])
        );
    }

    /// The field is additive, so a requester that predates it must still be understood — otherwise
    /// a rolling deploy would break every client that had not shipped the new struct yet.
    #[test]
    fn a_payload_without_the_field_decodes_as_vanilla() {
        let old = inputs();
        let mut encoded = Vec::new();
        ciborium::into_writer(
            &PreLightGuardInputs {
                version: old.version,
                live_image: old.live_image.clone(),
                credential_image: old.credential_image.clone(),
                hashes_json: old.hashes_json.clone(),
                challenge_image_key: old.challenge_image_key,
                challenge_image_iv: old.challenge_image_iv,
                match_threshold: old.match_threshold,
            },
            &mut encoded,
        )
        .expect("encoding should succeed");

        let decoded = MatchInputs::from_cbor(&encoded).expect("an old payload should still decode");

        assert_eq!(decoded.light_guard_image, None);
        assert_eq!(decoded.live_image, old.live_image);
        assert_eq!(decoded.credential_image, old.credential_image);
    }

    #[test]
    fn challenge_round_trips_an_rp_shaped_blob() {
        let (key, iv) = key_and_iv();
        let blob = encrypt_challenge(b"challenge-frame", &key, &iv).expect("should encrypt");

        assert_eq!(
            decrypt_challenge(&blob, &key, &iv).expect("should decrypt"),
            b"challenge-frame"
        );
    }

    #[test]
    fn challenge_rejects_the_wrong_key() {
        // Also what a host swapping the fetched object looks like from in here.
        let (key, iv) = key_and_iv();
        let (other_key, _) = key_and_iv();
        let blob = encrypt_challenge(b"challenge-frame", &key, &iv).expect("should encrypt");

        assert_eq!(
            decrypt_challenge(&blob, &other_key, &iv).err(),
            Some(Error::ChallengeDecryptFailed)
        );
    }

    #[test]
    fn challenge_rejects_the_wrong_iv() {
        let (key, iv) = key_and_iv();
        let (_, other_iv) = key_and_iv();
        let blob = encrypt_challenge(b"challenge-frame", &key, &iv).expect("should encrypt");

        assert_eq!(
            decrypt_challenge(&blob, &key, &other_iv).err(),
            Some(Error::ChallengeDecryptFailed)
        );
    }

    #[test]
    fn challenge_rejects_a_truncated_tag() {
        let (key, iv) = key_and_iv();
        let mut blob = encrypt_challenge(b"challenge-frame", &key, &iv).expect("should encrypt");
        blob.pop();

        assert_eq!(
            decrypt_challenge(&blob, &key, &iv).err(),
            Some(Error::ChallengeDecryptFailed)
        );
    }

    #[test]
    fn rejects_non_cbor_inputs() {
        assert_eq!(
            MatchInputs::from_cbor(b"not cbor framing").err(),
            Some(Error::Malformed)
        );
    }

    #[test]
    fn rejects_an_unsupported_version() {
        let mut inputs = inputs();
        inputs.version = CHANNEL_VERSION + 1;
        let encoded = inputs.to_cbor().expect("encoding should succeed");

        assert_eq!(
            MatchInputs::from_cbor(&encoded).err(),
            Some(Error::UnsupportedChannelVersion)
        );
    }

    #[test]
    fn results_round_trip_every_variant() {
        let success = MatchResult::Success(MatchToken::from_bytes(b"cose-sign1".to_vec()));
        let below = MatchResult::Failed(FailureReason::MatchBelowThreshold);
        let malformed = MatchResult::Failed(FailureReason::MalformedInputs);

        for result in [success, below, malformed] {
            let encoded = result.to_cbor().expect("encoding should succeed");

            assert_eq!(
                MatchResult::from_cbor(&encoded).expect("decoding should succeed"),
                result
            );
        }
    }

    #[test]
    fn rejects_non_cbor_results() {
        assert_eq!(
            MatchResult::from_cbor(b"not cbor framing").err(),
            Some(Error::Malformed)
        );
    }
}

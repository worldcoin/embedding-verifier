use std::io::Cursor;
use std::sync::Arc;

use enclave_types::{EnclaveError, MatchRequest, MatchResponse, MatchStatement};
use pontifex::Request;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{pcp, state::EnclaveState};

/// Statement format version.
const STATEMENT_VERSION: u8 = 1;

/// Placeholder statement signature until signing lands.
const DUMMY_SIGNATURE: [u8; 64] = [0u8; 64];

/// CBOR-framed match inputs carried by [`MatchRequest`].
/// Enclave-internal: the host only forwards the opaque payload.
#[derive(Serialize, Deserialize)]
pub(super) struct MatchInputs {
    /// Raw liveness image bytes.
    #[serde(with = "serde_bytes")]
    pub live_image: Vec<u8>,
    /// Raw credential image bytes (the Orb PCP thumbnail).
    #[serde(with = "serde_bytes")]
    pub credential_image: Vec<u8>,
    /// Raw `hashes.json` bytes from the PCP.
    #[serde(with = "serde_bytes")]
    pub hashes_json: Vec<u8>,
    /// Raw challenge image bytes (the RP-supplied face challenge).
    #[serde(with = "serde_bytes")]
    pub challenge_image: Vec<u8>,
    /// Minimum similarity the RP requires. Convenience gate only.
    pub match_threshold: f32,
}

impl MatchInputs {
    /// Decodes the CBOR-framed match inputs.
    fn from_cbor(bytes: &[u8]) -> Result<Self, EnclaveError> {
        ciborium::from_reader(Cursor::new(bytes)).map_err(|_| EnclaveError::MalformedMatchPayload)
    }
}

/// Runs a 3-way face match: the credential image against both the live and challenge
/// images.
///
/// The statement signature remains a placeholder.
pub async fn handler(
    state: Arc<EnclaveState>,
    request: MatchRequest,
) -> Result<MatchResponse, EnclaveError> {
    let payload = MatchInputs::from_cbor(&request.sealed_payload).inspect_err(|error| {
        tracing::warn!(
            ?error,
            route = MatchRequest::ROUTE_ID,
            "malformed match payload"
        );
    })?;

    // Bind the credential image to its PCP commitment.
    let binding = pcp::bind_credential_claim(&payload.credential_image, &payload.hashes_json);
    let credential_claim = binding.inspect_err(|error| {
        tracing::warn!(
            ?error,
            route = MatchRequest::ROUTE_ID,
            "pcp binding rejected"
        );
    })?;

    let live_image_hash: [u8; 32] = Sha256::digest(&payload.live_image).into();
    let challenger_image_hash: [u8; 32] = Sha256::digest(&payload.challenge_image).into();

    let scores = state.face_engine().compare_reference_to_probes(
        &payload.credential_image,
        &payload.live_image,
        &payload.challenge_image,
    )?;
    let live_coefficient = scores.live_similarity;
    let challenge_coefficient = scores.challenge_similarity;

    if live_coefficient < payload.match_threshold || challenge_coefficient < payload.match_threshold
    {
        tracing::warn!(
            live_coefficient,
            challenge_coefficient,
            threshold = payload.match_threshold,
            route = MatchRequest::ROUTE_ID,
            "match scored below threshold"
        );
        return Err(EnclaveError::MatchBelowThreshold);
    }

    let statement = MatchStatement {
        version: STATEMENT_VERSION,
        live_image_hash,
        credential_claim,
        challenger_image_hash,
        // Only the credential-vs-live score is surfaced.
        match_coefficient: live_coefficient,
    };

    // DUMMY: statement signing is not yet implemented.
    Ok(MatchResponse {
        statement,
        signature: DUMMY_SIGNATURE.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use enclave_types::{EnclaveError, MatchRequest};
    use sha2::{Digest, Sha256};

    use super::{DUMMY_SIGNATURE, MatchInputs, handler};
    use crate::{
        face_engine::{ComparisonScores, FaceComparator},
        state::EnclaveState,
        test_support::FailingAttestor,
    };

    struct ExpectedImages {
        credential: Vec<u8>,
        live: Vec<u8>,
        challenge: Vec<u8>,
    }

    struct MockFaceEngine {
        expected: Option<ExpectedImages>,
        result: Result<ComparisonScores, EnclaveError>,
    }

    impl MockFaceEngine {
        fn matching(
            credential: &[u8],
            live: &[u8],
            challenge: &[u8],
            live_similarity: f32,
            challenge_similarity: f32,
        ) -> Self {
            Self {
                expected: Some(ExpectedImages {
                    credential: credential.to_vec(),
                    live: live.to_vec(),
                    challenge: challenge.to_vec(),
                }),
                result: Ok(ComparisonScores {
                    live_similarity,
                    challenge_similarity,
                }),
            }
        }

        fn unused() -> Self {
            Self {
                expected: None,
                result: Err(EnclaveError::NotReady),
            }
        }
    }

    impl FaceComparator for MockFaceEngine {
        fn compare_reference_to_probes(
            &self,
            credential_image: &[u8],
            live_image: &[u8],
            challenge_image: &[u8],
        ) -> Result<ComparisonScores, EnclaveError> {
            let expected = self
                .expected
                .as_ref()
                .expect("mock Face Engine was called unexpectedly");
            assert_eq!(credential_image, expected.credential);
            assert_eq!(live_image, expected.live);
            assert_eq!(challenge_image, expected.challenge);
            self.result
        }
    }

    fn state_with(face_engine: MockFaceEngine) -> Arc<EnclaveState> {
        Arc::new(EnclaveState::generate(
            Arc::new(FailingAttestor),
            Arc::new(face_engine),
        ))
    }

    fn encode_match(
        live: &[u8],
        credential: &[u8],
        hashes_json: &[u8],
        challenge: &[u8],
        match_threshold: f32,
    ) -> Vec<u8> {
        let payload = MatchInputs {
            live_image: live.to_vec(),
            credential_image: credential.to_vec(),
            hashes_json: hashes_json.to_vec(),
            challenge_image: challenge.to_vec(),
            match_threshold,
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&payload, &mut cbor).expect("cbor encoding should succeed");
        cbor
    }

    fn hashes_json_for(image: &[u8]) -> Vec<u8> {
        let hash = hex::encode(Sha256::digest(image));
        format!(r#"{{"thumbnail.png":"{hash}"}}"#).into_bytes()
    }

    fn request(sealed_payload: Vec<u8>) -> MatchRequest {
        MatchRequest { sealed_payload }
    }

    #[tokio::test]
    async fn handler_produces_statement_for_valid_payload() {
        let live = b"liveness-frame";
        let credential = b"credential-thumbnail";
        let challenge = b"challenge-frame";
        let state = state_with(MockFaceEngine::matching(
            credential, live, challenge, 0.92, 0.87,
        ));
        let hashes_json = hashes_json_for(credential);
        let sealed_payload = encode_match(live, credential, &hashes_json, challenge, 0.5);

        let response = handler(state, request(sealed_payload))
            .await
            .expect("match should produce a statement");

        let statement = &response.statement;
        assert_eq!(statement.version, 1);
        assert_eq!(statement.live_image_hash, Sha256::digest(live).as_slice());
        assert_eq!(
            statement.credential_claim,
            Sha256::digest(&hashes_json).as_slice()
        );
        assert_eq!(
            statement.challenger_image_hash,
            Sha256::digest(challenge).as_slice()
        );
        assert_eq!(response.signature, DUMMY_SIGNATURE.to_vec());
        assert_eq!(statement.match_coefficient.to_bits(), 0.92f32.to_bits());
    }

    #[tokio::test]
    async fn handler_rejects_non_cbor_plaintext() {
        let state = state_with(MockFaceEngine::unused());

        let result = handler(state, request(b"not cbor framing".to_vec())).await;

        assert_eq!(result, Err(EnclaveError::MalformedMatchPayload));
    }

    #[tokio::test]
    async fn handler_rejects_pcp_binding_mismatch() {
        let state = state_with(MockFaceEngine::unused());
        let hashes_json = hashes_json_for(b"the-enrolled-image");
        let sealed_payload = encode_match(
            b"liveness",
            b"a-different-image",
            &hashes_json,
            b"challenge",
            0.5,
        );

        let result = handler(state, request(sealed_payload)).await;

        assert_eq!(result, Err(EnclaveError::ThumbnailHashMismatch));
    }

    #[tokio::test]
    async fn handler_rejects_match_below_threshold() {
        let credential = b"credential-thumbnail";
        let live = b"liveness";
        let challenge = b"challenge";
        let state = state_with(MockFaceEngine::matching(
            credential, live, challenge, 0.95, 0.85,
        ));
        let hashes_json = hashes_json_for(credential);
        let sealed_payload = encode_match(live, credential, &hashes_json, challenge, 0.9);

        let result = handler(state, request(sealed_payload)).await;

        assert_eq!(result, Err(EnclaveError::MatchBelowThreshold));
    }
}

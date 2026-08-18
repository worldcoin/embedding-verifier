use std::io::Cursor;
use std::sync::Arc;

use enclave_types::{
    EnclaveError, MatchOutcome, MatchRequest, MatchResponse, MatchStatement, sealing::ResponseKey,
};
use pontifex::Request;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{pcp, state::EnclaveState};

/// Statement format version.
const STATEMENT_VERSION: u8 = 1;

/// Placeholder statement signature until signing lands.
const DUMMY_SIGNATURE: [u8; 64] = [0u8; 64];

/// The decrypted, CBOR-framed plaintext of a [`MatchRequest`]'s sealed payload.
/// Enclave-internal: the host only forwards the opaque ciphertext.
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
    let (plaintext, response_key) = state.unseal(&request.sealed_payload).inspect_err(|error| {
        tracing::warn!(
            ?error,
            route = MatchRequest::ROUTE_ID,
            "failed to unseal request"
        );
    })?;

    let payload = MatchInputs::from_cbor(&plaintext).inspect_err(|error| {
        tracing::warn!(
            ?error,
            route = MatchRequest::ROUTE_ID,
            "malformed match payload"
        );
    })?;

    // Bind the credential image to its PCP commitment.
    let credential_claim = pcp::verify_pcp(&payload.credential_image, &payload.hashes_json)
        .inspect_err(|error| {
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
    seal_outcome(
        &response_key,
        &MatchOutcome {
            statement,
            signature: DUMMY_SIGNATURE.to_vec(),
        },
    )
}

/// Seals the outcome for the client that sent the request.
///
/// The host relays the result unread: the statement commits to biometric-derived values,
/// and the host is outside the trust boundary.
fn seal_outcome(
    response_key: &ResponseKey,
    outcome: &MatchOutcome,
) -> Result<MatchResponse, EnclaveError> {
    let mut cbor = Vec::new();
    ciborium::into_writer(outcome, &mut cbor).map_err(|error| {
        tracing::error!(?error, "failed to encode the match outcome");
        EnclaveError::MalformedMatchPayload
    })?;

    let sealed_outcome = response_key.seal(&cbor).map_err(|error| {
        tracing::error!(?error, "failed to seal the match outcome");
        EnclaveError::EncryptFailed
    })?;

    Ok(MatchResponse { sealed_outcome })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use enclave_types::{
        EnclaveError, MatchOutcome, MatchRequest, MatchResponse, sealing, sealing::ResponseKey,
    };
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
        Arc::new(
            EnclaveState::generate(Arc::new(FailingAttestor), Arc::new(face_engine))
                .expect("state should generate"),
        )
    }

    /// Returns the framed request and the key its response will be sealed under.
    fn seal_to(state: &EnclaveState, plaintext: &[u8]) -> (Vec<u8>, ResponseKey) {
        sealing::seal_request(state.encryption_public_key(), plaintext)
            .expect("sealing should succeed")
    }

    fn seal_match(
        state: &EnclaveState,
        live: &[u8],
        credential: &[u8],
        hashes_json: &[u8],
        challenge: &[u8],
        match_threshold: f32,
    ) -> (Vec<u8>, ResponseKey) {
        let payload = MatchInputs {
            live_image: live.to_vec(),
            credential_image: credential.to_vec(),
            hashes_json: hashes_json.to_vec(),
            challenge_image: challenge.to_vec(),
            match_threshold,
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&payload, &mut cbor).expect("cbor encoding should succeed");

        seal_to(state, &cbor)
    }

    /// Opens an outcome the way the requesting client does.
    fn open_outcome(response_key: &ResponseKey, response: &MatchResponse) -> MatchOutcome {
        let cbor = response_key
            .open(&response.sealed_outcome)
            .expect("outcome should open under the request's response key");

        ciborium::from_reader(cbor.as_slice()).expect("outcome should decode")
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
        let (sealed_payload, response_key) =
            seal_match(&state, live, credential, &hashes_json, challenge, 0.5);

        let response = handler(state, request(sealed_payload))
            .await
            .expect("match should produce a statement");

        let outcome = open_outcome(&response_key, &response);
        let statement = &outcome.statement;
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
        assert_eq!(outcome.signature, DUMMY_SIGNATURE.to_vec());
        assert_eq!(statement.match_coefficient.to_bits(), 0.92f32.to_bits());
    }

    #[tokio::test]
    async fn outcome_is_sealed_to_the_requesting_client_only() {
        let live = b"liveness-frame";
        let credential = b"credential-thumbnail";
        let challenge = b"challenge-frame";
        let state = state_with(MockFaceEngine::matching(
            credential, live, challenge, 0.92, 0.87,
        ));
        let hashes_json = hashes_json_for(credential);
        let (sealed_payload, _) =
            seal_match(&state, live, credential, &hashes_json, challenge, 0.5);
        // A second request derives an unrelated response key.
        let (_, other_key) = seal_match(&state, live, credential, &hashes_json, challenge, 0.5);

        let response = handler(state, request(sealed_payload))
            .await
            .expect("match should produce a statement");

        assert!(other_key.open(&response.sealed_outcome).is_err());
        // The plaintext statement never appears in the relayed bytes.
        assert!(
            !response
                .sealed_outcome
                .windows(32)
                .any(|window| window == Sha256::digest(live).as_slice())
        );
    }

    #[tokio::test]
    async fn handler_rejects_undecryptable_payload() {
        let state = state_with(MockFaceEngine::unused());

        let result = handler(state, request(vec![0u8; 64])).await;

        assert_eq!(result, Err(EnclaveError::DecryptFailed));
    }

    #[tokio::test]
    async fn handler_rejects_non_cbor_plaintext() {
        let state = state_with(MockFaceEngine::unused());
        let (sealed_payload, _) = seal_to(&state, b"not cbor framing");

        let result = handler(state, request(sealed_payload)).await;

        assert_eq!(result, Err(EnclaveError::MalformedMatchPayload));
    }

    #[tokio::test]
    async fn handler_rejects_pcp_binding_mismatch() {
        let state = state_with(MockFaceEngine::unused());
        let hashes_json = hashes_json_for(b"the-enrolled-image");
        let (sealed_payload, _) = seal_match(
            &state,
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
        let (sealed_payload, _) =
            seal_match(&state, live, credential, &hashes_json, challenge, 0.9);

        let result = handler(state, request(sealed_payload)).await;

        assert_eq!(result, Err(EnclaveError::MatchBelowThreshold));
    }
}

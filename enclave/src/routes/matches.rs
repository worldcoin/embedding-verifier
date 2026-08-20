use std::sync::Arc;

use crypto::match_token::MatchClaims;
use crypto::payload::{MatchInputs, MatchOutcomePayload, PayloadError, RejectReason};
use crypto::sealed_channel::{SealedRequest, SealedResponse, UnwrapErr};
use enclave_types::{EnclaveError, MatchOutcome, MatchRequest, MatchResponse};
use getrandom::SysRng;
use pontifex::Request;
use sha2::{Digest, Sha256};

use crate::{challenge, pcp, state::EnclaveState};

/// Runs a 3-way face match: the credential image against both the live and challenge images.
///
/// Request and outcome are both sealed to this boot's channel, so the host learns only
/// [`MatchOutcome`].
///
/// # Errors
///
/// Returns [`EnclaveError`] only for what the host may see. A face that did not match is *not* an
/// error — it is a sealed [`RejectReason`] inside a successful response.
pub async fn handler(
    state: Arc<EnclaveState>,
    request: MatchRequest,
) -> Result<MatchResponse, EnclaveError> {
    let (plaintext, sealer) = state
        .responder()
        .open(&SealedRequest::from_bytes(request.body))
        .map_err(|error| {
            tracing::warn!(
                ?error,
                route = MatchRequest::ROUTE_ID,
                "failed to open sealed request"
            );
            EnclaveError::BadRequest
        })?;

    let inputs = MatchInputs::from_cbor(&plaintext).map_err(|error| {
        tracing::warn!(
            ?error,
            route = MatchRequest::ROUTE_ID,
            "unusable match payload"
        );
        match error {
            PayloadError::UnsupportedVersion | PayloadError::Malformed => EnclaveError::BadRequest,
            PayloadError::Encoding => EnclaveError::Internal,
        }
    })?;

    let challenge_image = challenge::decrypt(
        &request.challenge_ciphertext,
        &inputs.challenge_image_key,
        &inputs.challenge_image_iv,
    )?;

    let (outcome, payload) = match evaluate(&state, &inputs, &challenge_image)? {
        Ok(statement) => (MatchOutcome::Statement, Ok(sign(&state, &statement)?)),
        Err(reason) => (MatchOutcome::Rejected, Err(reason)),
    };

    Ok(MatchResponse {
        outcome,
        ciphertext: seal(sealer, &payload)?.into_bytes(),
    })
}

/// Evaluates the opened inputs.
///
/// The nesting is the confidentiality split: the outer `Err` is what the host sees, the inner
/// `Err` is a [`RejectReason`] only the requester sees.
fn evaluate(
    state: &EnclaveState,
    inputs: &MatchInputs,
    challenge_image: &[u8],
) -> Result<Result<MatchClaims, RejectReason>, EnclaveError> {
    // Binds the credential image to the hash its PCP commits. A commitment, not proof of
    // enrollment — nothing here checks who issued the PCP.
    let credential_claim =
        match pcp::bind_credential_claim(&inputs.credential_image, &inputs.hashes_json) {
            Ok(claim) => claim,
            Err(pcp::PcpError::InvalidHashesJson) => {
                tracing::warn!(route = MatchRequest::ROUTE_ID, "malformed hashes.json");
                return Err(EnclaveError::BadRequest);
            }
            Err(pcp::PcpError::ThumbnailHashMismatch) => {
                tracing::warn!(route = MatchRequest::ROUTE_ID, "pcp binding rejected");
                return Ok(Err(RejectReason::ThumbnailHashMismatch));
            }
        };

    let scores = state.face_engine().compare_reference_to_probes(
        &inputs.credential_image,
        &inputs.live_image,
        challenge_image,
    )?;

    if scores.live_similarity < inputs.match_threshold
        || scores.challenge_similarity < inputs.match_threshold
    {
        // Scores stay out of the log: they measure a person, and the log has no sealed channel.
        tracing::warn!(
            route = MatchRequest::ROUTE_ID,
            "match scored below threshold"
        );
        return Ok(Err(RejectReason::MatchBelowThreshold));
    }

    Ok(Ok(MatchClaims {
        live_image_hash: Sha256::digest(&inputs.live_image).into(),
        credential_claim,
        challenger_image_hash: Sha256::digest(challenge_image).into(),
        // Only the credential-vs-live score is surfaced; the challenge comparison is a gate.
        match_coefficient: scores.live_similarity,
    }))
}

/// Signs a statement with this boot's signing key.
fn sign(state: &EnclaveState, statement: &MatchClaims) -> Result<Vec<u8>, EnclaveError> {
    state.match_token_signer().sign(statement).map_err(|error| {
        tracing::error!(?error, "failed to sign the match statement");
        EnclaveError::Internal
    })
}

/// Seals the authoritative outcome back to the requester.
fn seal(
    sealer: crypto::sealed_channel::ResponseSealer,
    payload: &MatchOutcomePayload,
) -> Result<SealedResponse, EnclaveError> {
    let encoded = crypto::payload::encode_outcome(payload).map_err(|error| {
        tracing::error!(?error, "failed to encode the match outcome");
        EnclaveError::Internal
    })?;

    sealer
        .seal(&encoded, &mut UnwrapErr(SysRng))
        .map_err(|error| {
            tracing::error!(?error, "failed to seal the match response");
            EnclaveError::Internal
        })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aes_gcm::{
        Aes256Gcm, Key, KeyInit,
        aead::{Aead, Nonce},
    };
    use crypto::match_token;
    use crypto::payload::{
        CHALLENGE_IV_LEN, CHALLENGE_KEY_LEN, MatchInputs, RejectReason, decode_outcome,
    };
    use crypto::sealed_channel::{
        CHANNEL_VERSION, Requester, ResponseOpener, SealedResponse, UnwrapErr,
    };
    use enclave_types::{EnclaveError, MatchOutcome, MatchRequest};
    use getrandom::SysRng;
    use sha2::{Digest, Sha256};

    use super::handler;
    use crate::{
        face_engine::{ComparisonScores, FaceComparator},
        state::EnclaveState,
        test_support::FailingAttestor,
    };

    const KEY: [u8; CHALLENGE_KEY_LEN] = [7u8; CHALLENGE_KEY_LEN];
    const IV: [u8; CHALLENGE_IV_LEN] = [9u8; CHALLENGE_IV_LEN];
    const CREDENTIAL: &[u8] = b"credential-thumbnail";
    const LIVE: &[u8] = b"liveness-frame";
    const CHALLENGE: &[u8] = b"challenge-frame";

    struct MockFaceEngine {
        result: Result<ComparisonScores, EnclaveError>,
    }

    impl MockFaceEngine {
        const fn scoring(live: f32, challenge: f32) -> Self {
            Self {
                result: Ok(ComparisonScores {
                    live_similarity: live,
                    challenge_similarity: challenge,
                }),
            }
        }

        const fn failing(error: EnclaveError) -> Self {
            Self { result: Err(error) }
        }
    }

    impl FaceComparator for MockFaceEngine {
        fn compare_reference_to_probes(
            &self,
            credential_image: &[u8],
            live_image: &[u8],
            challenge_image: &[u8],
        ) -> Result<ComparisonScores, EnclaveError> {
            // The challenge image must arrive decrypted.
            assert_eq!(credential_image, CREDENTIAL);
            assert_eq!(live_image, LIVE);
            assert_eq!(challenge_image, CHALLENGE);
            self.result
        }
    }

    fn state_with(face_engine: MockFaceEngine) -> Arc<EnclaveState> {
        Arc::new(EnclaveState::generate(
            Arc::new(FailingAttestor),
            Arc::new(face_engine),
        ))
    }

    fn hashes_json_for(image: &[u8]) -> Vec<u8> {
        let hash = hex::encode(Sha256::digest(image));
        format!(r#"{{"thumbnail.png":"{hash}"}}"#).into_bytes()
    }

    fn inputs(credential: &[u8], threshold: f32) -> MatchInputs {
        MatchInputs {
            version: CHANNEL_VERSION,
            live_image: LIVE.to_vec(),
            credential_image: credential.to_vec(),
            hashes_json: hashes_json_for(credential),
            challenge_image_key: KEY,
            challenge_image_iv: IV,
            match_threshold: threshold,
        }
    }

    /// Encrypts the challenge the way the RP does.
    fn challenge_blob(key: &[u8; CHALLENGE_KEY_LEN]) -> Vec<u8> {
        Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key))
            .encrypt(&Nonce::<Aes256Gcm>::from(IV), CHALLENGE)
            .expect("encryption should succeed")
    }

    /// Seals `inputs` to `state` and pairs the request with a freshly encrypted challenge blob.
    fn request_for(state: &EnclaveState, inputs: &MatchInputs) -> (ResponseOpener, MatchRequest) {
        let requester = Requester::new(state.encryption_public_key()).expect("valid key");
        let plaintext = inputs.to_cbor().expect("encoding should succeed");
        let (sealed, opener) = requester
            .seal(&plaintext, &mut UnwrapErr(SysRng))
            .expect("sealing should succeed");

        (
            opener,
            MatchRequest {
                body: sealed.into_bytes(),
                challenge_ciphertext: challenge_blob(&KEY),
            },
        )
    }

    #[tokio::test]
    async fn seals_a_signed_statement_to_the_requester() {
        let state = state_with(MockFaceEngine::scoring(0.92, 0.87));
        // Outlives the move into `handler`, so the statement can be checked against this boot's key.
        let signer = Arc::clone(&state);
        let inputs = inputs(CREDENTIAL, 0.5);
        let (opener, request) = request_for(&state, &inputs);

        let response = handler(state, request).await.expect("match should succeed");

        assert_eq!(response.outcome, MatchOutcome::Statement);
        let plaintext = opener
            .open(&SealedResponse::from_bytes(response.ciphertext))
            .expect("the requester should open its own response");
        let token = decode_outcome(&plaintext)
            .expect("payload should decode")
            .expect("payload should hold a statement");

        // The statement verifies under the key this boot attests, and commits to every input.
        let statement = match_token::verify(&token, signer.match_token_signer().public_key())
            .expect("statement should verify");
        assert_eq!(statement.live_image_hash, Sha256::digest(LIVE).as_slice());
        assert_eq!(
            statement.credential_claim,
            Sha256::digest(&inputs.hashes_json).as_slice()
        );
        assert_eq!(
            statement.challenger_image_hash,
            Sha256::digest(CHALLENGE).as_slice()
        );
    }

    #[tokio::test]
    async fn a_below_threshold_score_is_a_sealed_rejection_not_an_error() {
        let state = state_with(MockFaceEngine::scoring(0.95, 0.40));
        let (opener, request) = request_for(&state, &inputs(CREDENTIAL, 0.9));

        let response = handler(state, request)
            .await
            .expect("a rejection is still a successful response");

        // The host sees only the coarse class...
        assert_eq!(response.outcome, MatchOutcome::Rejected);
        // ...while the reason travels sealed.
        let plaintext = opener
            .open(&SealedResponse::from_bytes(response.ciphertext))
            .expect("should open");
        assert_eq!(
            decode_outcome(&plaintext).expect("should decode"),
            Err(RejectReason::MatchBelowThreshold)
        );
    }

    #[tokio::test]
    async fn a_thumbnail_mismatch_is_a_sealed_rejection() {
        let state = state_with(MockFaceEngine::failing(EnclaveError::NotReady));
        let mut inputs = inputs(b"the-enrolled-image", 0.5);
        inputs.credential_image = b"a-different-image".to_vec();
        let (opener, request) = request_for(&state, &inputs);

        let response = handler(state, request)
            .await
            .expect("should seal a rejection");

        assert_eq!(response.outcome, MatchOutcome::Rejected);
        let plaintext = opener
            .open(&SealedResponse::from_bytes(response.ciphertext))
            .expect("should open");
        assert_eq!(
            decode_outcome(&plaintext).expect("should decode"),
            Err(RejectReason::ThumbnailHashMismatch)
        );
    }

    #[tokio::test]
    async fn no_score_appears_in_the_cleartext_response() {
        let state = state_with(MockFaceEngine::scoring(0.92, 0.87));
        let (_, request) = request_for(&state, &inputs(CREDENTIAL, 0.5));

        let response = handler(state, request).await.expect("match should succeed");

        // The credential claim is the most sensitive thing the host must not learn.
        let claim = Sha256::digest(hashes_json_for(CREDENTIAL));
        assert!(
            !response
                .ciphertext
                .windows(claim.len())
                .any(|window| window == claim.as_slice())
        );
    }

    #[tokio::test]
    async fn rejects_a_request_sealed_to_another_boot() {
        let state = state_with(MockFaceEngine::failing(EnclaveError::NotReady));
        let other = state_with(MockFaceEngine::failing(EnclaveError::NotReady));
        let (_, request) = request_for(&other, &inputs(CREDENTIAL, 0.5));

        assert_eq!(
            handler(state, request).await.err(),
            Some(EnclaveError::BadRequest)
        );
    }

    #[tokio::test]
    async fn rejects_a_non_cbor_plaintext() {
        let state = state_with(MockFaceEngine::failing(EnclaveError::NotReady));
        let requester = Requester::new(state.encryption_public_key()).expect("valid key");
        let (sealed, _) = requester
            .seal(b"not cbor framing", &mut UnwrapErr(SysRng))
            .expect("sealing should succeed");

        let result = handler(
            state,
            MatchRequest {
                body: sealed.into_bytes(),
                challenge_ciphertext: challenge_blob(&KEY),
            },
        )
        .await;

        assert_eq!(result.err(), Some(EnclaveError::BadRequest));
    }

    #[tokio::test]
    async fn rejects_an_unsupported_payload_version() {
        let state = state_with(MockFaceEngine::failing(EnclaveError::NotReady));
        let mut inputs = inputs(CREDENTIAL, 0.5);
        inputs.version = CHANNEL_VERSION + 1;
        let (_, request) = request_for(&state, &inputs);

        assert_eq!(
            handler(state, request).await.err(),
            Some(EnclaveError::BadRequest)
        );
    }

    #[tokio::test]
    async fn attributes_a_bad_challenge_blob_separately() {
        // The blob is the one input the host supplied, so it must not read as a client error.
        let state = state_with(MockFaceEngine::failing(EnclaveError::NotReady));
        let (_, mut request) = request_for(&state, &inputs(CREDENTIAL, 0.5));
        request.challenge_ciphertext = challenge_blob(&[1u8; CHALLENGE_KEY_LEN]);

        assert_eq!(
            handler(state, request).await.err(),
            Some(EnclaveError::ChallengeDecryptFailed)
        );
    }

    #[tokio::test]
    async fn surfaces_an_image_quality_failure_in_the_clear() {
        // A client has to know to retake the photo, so this one is not sealed.
        let state = state_with(MockFaceEngine::failing(EnclaveError::ImageAnalysisFailed));
        let (_, request) = request_for(&state, &inputs(CREDENTIAL, 0.5));

        assert_eq!(
            handler(state, request).await.err(),
            Some(EnclaveError::ImageAnalysisFailed)
        );
    }

    #[tokio::test]
    async fn a_second_requester_cannot_open_the_response() {
        let state = state_with(MockFaceEngine::scoring(0.92, 0.87));
        let (_, request) = request_for(&state, &inputs(CREDENTIAL, 0.5));
        // A different ephemeral, so a different exporter secret.
        let (eavesdropper, _) = request_for(&state, &inputs(CREDENTIAL, 0.5));

        let response = handler(state, request).await.expect("match should succeed");

        assert!(
            eavesdropper
                .open(&SealedResponse::from_bytes(response.ciphertext))
                .is_err()
        );
    }
}

use std::sync::Arc;

use enclave_types::{EnclaveError, MatchRequest, MatchResponse, MatchStatement};
use pontifex::Request;
use sha2::{Digest, Sha256};

use crate::pcp::{self, SealedMatchPayload};
use crate::state::EnclaveState;

/// Statement format version emitted by this skeleton.
const STATEMENT_VERSION: u8 = 1;

/// Placeholder similarity score until the face engine is integrated. Chosen at the
/// top of the range so the threshold gate passes for any sane RP threshold.
const DUMMY_MATCH_COEFFICIENT: f32 = 1.0;

/// Placeholder statement signature until output signing is implemented.
const DUMMY_SIGNATURE: [u8; 64] = [0u8; 64];

/// Runs a 3-way face match: the credential image is compared against both the live
/// image and the RP-supplied challenge image.
///
/// SKELETON: everything that does not require the face engine or output signing is
/// real — the payload is unsealed, the credential image is bound to its PCP
/// `hashes.json`, the image hashes are committed, and the threshold gate is enforced.
/// The two face comparisons (`match_coefficient`) and the statement `signature` are
/// **dummies**; this response is not usable for real verification.
pub async fn handler(
    state: Arc<EnclaveState>,
    request: MatchRequest,
) -> Result<MatchResponse, EnclaveError> {
    let plaintext = state.unseal(&request.sealed_payload).inspect_err(|error| {
        tracing::warn!(
            ?error,
            route = MatchRequest::ROUTE_ID,
            "failed to unseal request"
        );
    })?;

    let payload = SealedMatchPayload::from_cbor(&plaintext).inspect_err(|error| {
        tracing::warn!(
            ?error,
            route = MatchRequest::ROUTE_ID,
            "malformed match payload"
        );
    })?;

    // Real (no face engine needed): bind the credential image to its PCP commitment.
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

    // DUMMY: the face-engine comparisons are not yet implemented. Both the
    // credential-vs-live and credential-vs-challenge comparisons must clear the
    // RP-supplied threshold, otherwise no statement is issued.
    let live_coefficient = DUMMY_MATCH_COEFFICIENT;
    let challenge_coefficient = DUMMY_MATCH_COEFFICIENT;
    if live_coefficient < payload.match_threshold || challenge_coefficient < payload.match_threshold
    {
        tracing::warn!(
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
        // Only the credential-vs-live score is surfaced; the challenge comparison is
        // enforced above and vouched for by issuing this statement.
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

    use crypto_box::{PublicKey, aead::OsRng};
    use enclave_types::{EnclaveError, MatchRequest};
    use sha2::{Digest, Sha256};

    use super::{DUMMY_SIGNATURE, handler};
    use crate::pcp::SealedMatchPayload;
    use crate::state::EnclaveState;

    fn seal_to(state: &EnclaveState, plaintext: &[u8]) -> Vec<u8> {
        let public_key = PublicKey::from(state.transit_public_key());
        public_key
            .seal(&mut OsRng, plaintext)
            .expect("sealing should succeed")
    }

    fn seal_match(
        state: &EnclaveState,
        live: &[u8],
        credential: &[u8],
        hashes_json: &[u8],
        challenge: &[u8],
        match_threshold: f32,
    ) -> Vec<u8> {
        let payload = SealedMatchPayload {
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

    fn hashes_json_for(image: &[u8]) -> Vec<u8> {
        let hash = hex::encode(Sha256::digest(image));
        format!(r#"{{"thumbnail.png":"{hash}"}}"#).into_bytes()
    }

    fn request(sealed_payload: Vec<u8>) -> MatchRequest {
        MatchRequest { sealed_payload }
    }

    #[tokio::test]
    async fn handler_produces_statement_for_valid_payload() {
        let state = Arc::new(EnclaveState::generate());
        let live = b"liveness-frame";
        let credential = b"credential-thumbnail";
        let challenge = b"challenge-frame";
        let hashes_json = hashes_json_for(credential);
        let sealed_payload = seal_match(&state, live, credential, &hashes_json, challenge, 0.5);

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
        // Skeleton dummies.
        assert_eq!(response.signature, DUMMY_SIGNATURE.to_vec());
        assert_eq!(statement.match_coefficient.to_bits(), 1.0f32.to_bits());
    }

    #[tokio::test]
    async fn handler_rejects_undecryptable_payload() {
        let state = Arc::new(EnclaveState::generate());

        let result = handler(state, request(vec![0u8; 64])).await;

        assert_eq!(result, Err(EnclaveError::DecryptFailed));
    }

    #[tokio::test]
    async fn handler_rejects_non_cbor_plaintext() {
        let state = Arc::new(EnclaveState::generate());
        let sealed_payload = seal_to(&state, b"not cbor framing");

        let result = handler(state, request(sealed_payload)).await;

        assert_eq!(result, Err(EnclaveError::MalformedPcpPayload));
    }

    #[tokio::test]
    async fn handler_rejects_pcp_binding_mismatch() {
        let state = Arc::new(EnclaveState::generate());
        let hashes_json = hashes_json_for(b"the-enrolled-image");
        let sealed_payload = seal_match(
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
        let state = Arc::new(EnclaveState::generate());
        let credential = b"credential-thumbnail";
        let hashes_json = hashes_json_for(credential);
        // A threshold above the dummy coefficient (1.0) forces the gate to reject.
        let sealed_payload = seal_match(
            &state,
            b"liveness",
            credential,
            &hashes_json,
            b"challenge",
            1.5,
        );

        let result = handler(state, request(sealed_payload)).await;

        assert_eq!(result, Err(EnclaveError::MatchBelowThreshold));
    }
}

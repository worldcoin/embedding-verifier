use std::io::Cursor;
use std::sync::Arc;

use enclave_types::{EnclaveError, MatchRequest, MatchResponse, MatchStatement};
use pontifex::Request;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::pcp;
use crate::state::EnclaveState;

/// Statement format version.
const STATEMENT_VERSION: u8 = 1;

/// Placeholder similarity score until the face engine lands; clears any sane threshold.
const DUMMY_MATCH_COEFFICIENT: f32 = 1.0;

/// Placeholder statement signature until signing lands.
const DUMMY_SIGNATURE: [u8; 64] = [0u8; 64];

/// The decrypted, CBOR-framed plaintext of a [`MatchRequest`]'s sealed box.
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
/// SKELETON: unseal, PCP binding, hashing, and the threshold gate are real; the face
/// comparisons and the statement signature are dummies.
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

    // DUMMY comparisons: both must clear the threshold or no statement is issued.
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

    use crypto_box::{PublicKey, aead::OsRng};
    use enclave_types::{EnclaveError, MatchRequest};
    use sha2::{Digest, Sha256};

    use super::{DUMMY_SIGNATURE, MatchInputs, handler};
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

        assert_eq!(result, Err(EnclaveError::MalformedMatchPayload));
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

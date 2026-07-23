use std::sync::Arc;

use enclave_types::{EnclaveError, MatchMode, MatchRequest, MatchResponse, MatchStatement};
use pontifex::Request;
use sha2::{Digest, Sha256};

use crate::pcp::{self, SealedMatchPayload};
use crate::state::EnclaveState;

/// Statement format version emitted by this skeleton.
const STATEMENT_VERSION: u8 = 1;

/// Placeholder similarity score until the face engine is integrated.
const DUMMY_MATCH_COEFFICIENT: f32 = 1.0;

/// Placeholder statement signature until output signing is implemented.
const DUMMY_SIGNATURE: [u8; 64] = [0u8; 64];

/// Runs a 2-way face match.
///
/// SKELETON: everything that does not require the face engine or output signing is
/// real — the payload is unsealed and the credential image is bound to its PCP
/// `hashes.json`. The face comparison (`match_coefficient`) and the statement
/// `signature` are **dummies**; this response is not usable for real verification.
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

    let pcp_thumbnail_hash: [u8; 32] = Sha256::digest(&payload.credential_image).into();
    let live_image_hash: [u8; 32] = Sha256::digest(&payload.live_image).into();

    // DUMMY: the face-engine comparison is not yet implemented.
    let match_coefficient = DUMMY_MATCH_COEFFICIENT;

    let statement = MatchStatement {
        version: STATEMENT_VERSION,
        mode: MatchMode::TwoWay,
        subject_binding: request.subject_binding,
        pcp_thumbnail_hash,
        live_image_hash,
        credential_claim,
        match_coefficient,
        similarity_threshold: request.similarity_threshold,
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
    use enclave_types::{EnclaveError, MatchMode, MatchRequest};
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
    ) -> Vec<u8> {
        let payload = SealedMatchPayload {
            live_image: live.to_vec(),
            credential_image: credential.to_vec(),
            hashes_json: hashes_json.to_vec(),
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
        MatchRequest {
            sealed_payload,
            subject_binding: b"subject".to_vec(),
            similarity_threshold: 0.5,
        }
    }

    #[tokio::test]
    async fn handler_produces_statement_for_valid_payload() {
        let state = Arc::new(EnclaveState::generate());
        let live = b"liveness-frame";
        let credential = b"credential-thumbnail";
        let hashes_json = hashes_json_for(credential);
        let sealed_payload = seal_match(&state, live, credential, &hashes_json);

        let response = handler(state, request(sealed_payload))
            .await
            .expect("match should produce a statement");

        let statement = &response.statement;
        assert_eq!(statement.mode, MatchMode::TwoWay);
        assert_eq!(statement.subject_binding, b"subject");
        assert_eq!(
            statement.credential_claim,
            Sha256::digest(&hashes_json).as_slice()
        );
        assert_eq!(
            statement.pcp_thumbnail_hash,
            Sha256::digest(credential).as_slice()
        );
        assert_eq!(statement.live_image_hash, Sha256::digest(live).as_slice());
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
        let sealed_payload = seal_match(&state, b"liveness", b"a-different-image", &hashes_json);

        let result = handler(state, request(sealed_payload)).await;

        assert_eq!(result, Err(EnclaveError::ThumbnailHashMismatch));
    }
}

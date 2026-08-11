use std::io::Cursor;
use std::sync::Arc;

use enclave_types::{
    CHANNEL_VERSION, EnclaveError, MatchOutcome, MatchOutcomePayload, MatchRequest, MatchResponse,
    MatchStatement, RejectReason,
};
use pontifex::Request;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::pcp::{self, PcpError};
use crate::state::{EnclaveState, ResponseSealer};

/// Statement format version.
const STATEMENT_VERSION: u8 = 1;

/// Placeholder similarity score until the face engine lands; clears any sane threshold.
const DUMMY_MATCH_COEFFICIENT: f32 = 1.0;

/// The decrypted, CBOR-framed plaintext of a [`MatchRequest`]'s HPKE ciphertext.
/// Enclave-internal: the host only forwards the opaque ciphertext.
#[derive(Serialize, Deserialize)]
pub(super) struct MatchInputs {
    /// Channel version the client believes it is speaking.
    ///
    /// The authoritative gate is the HPKE `info`, which binds the same value — a client
    /// on another version cannot open a channel at all. This field only catches a client
    /// that is internally inconsistent, and makes that legible in the enclave log rather
    /// than indistinguishable from a corrupt payload.
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
    /// Raw challenge image bytes (the RP-supplied face challenge).
    #[serde(with = "serde_bytes")]
    pub challenge_image: Vec<u8>,
    /// Minimum similarity the RP requires. Convenience gate only.
    pub match_threshold: f32,
}

impl MatchInputs {
    /// Decodes the CBOR-framed match inputs.
    fn from_cbor(bytes: &[u8]) -> Result<Self, EnclaveError> {
        ciborium::from_reader(Cursor::new(bytes)).map_err(|_| EnclaveError::BadRequest)
    }
}

/// Runs a 3-way face match: the credential image against both the live and challenge
/// images.
///
/// The request arrives over an HPKE channel keyed to this boot's attested transit key,
/// and the outcome — statement or rejection — goes back sealed to the same channel. The
/// host learns only [`MatchOutcome`], which is enough to pick a status code and count
/// failures and nothing more.
///
/// SKELETON: the channel, PCP binding, hashing, and the threshold gate are real; the face
/// comparisons are dummies.
///
/// # Errors
///
/// Returns [`EnclaveError::BadRequest`] when the request cannot be opened or its
/// plaintext is unusable — the only paths with no channel to seal a reason into — and
/// [`EnclaveError::Internal`] when the response itself cannot be sealed.
pub async fn handler(
    state: Arc<EnclaveState>,
    request: MatchRequest,
) -> Result<MatchResponse, EnclaveError> {
    let (plaintext, sealer) = state.open_request(&request.body).inspect_err(|error| {
        tracing::warn!(
            ?error,
            route = MatchRequest::ROUTE_ID,
            "failed to open request"
        );
    })?;

    let inputs = MatchInputs::from_cbor(&plaintext).inspect_err(|error| {
        tracing::warn!(
            ?error,
            route = MatchRequest::ROUTE_ID,
            "malformed match payload"
        );
    })?;

    if inputs.version != CHANNEL_VERSION {
        tracing::warn!(
            version = inputs.version,
            expected = CHANNEL_VERSION,
            route = MatchRequest::ROUTE_ID,
            "match payload declares an unsupported channel version"
        );
        return Err(EnclaveError::BadRequest);
    }

    let (outcome, payload) = match evaluate(&inputs)? {
        Ok(statement) => (MatchOutcome::Statement, Ok(statement)),
        Err(reason) => (MatchOutcome::Rejected, Err(reason)),
    };

    seal_response(sealer, outcome, &payload)
}

/// Evaluates the decrypted inputs.
///
/// The nesting is the confidentiality split: the outer `Err` is a coarse class the host
/// sees, the inner `Err` is a [`RejectReason`] only the client sees.
fn evaluate(inputs: &MatchInputs) -> Result<Result<MatchStatement, RejectReason>, EnclaveError> {
    // Bind the credential image to its PCP commitment.
    let credential_claim = match pcp::verify_pcp(&inputs.credential_image, &inputs.hashes_json) {
        Ok(claim) => claim,
        Err(PcpError::InvalidHashesJson) => {
            tracing::warn!(route = MatchRequest::ROUTE_ID, "malformed hashes.json");
            return Err(EnclaveError::BadRequest);
        }
        Err(PcpError::ThumbnailHashMismatch) => {
            tracing::warn!(route = MatchRequest::ROUTE_ID, "pcp binding rejected");
            return Ok(Err(RejectReason::ThumbnailHashMismatch));
        }
    };

    let live_image_hash: [u8; 32] = Sha256::digest(&inputs.live_image).into();
    let challenger_image_hash: [u8; 32] = Sha256::digest(&inputs.challenge_image).into();

    // DUMMY comparisons: both must clear the threshold or no statement is issued.
    let live_coefficient = DUMMY_MATCH_COEFFICIENT;
    let challenge_coefficient = DUMMY_MATCH_COEFFICIENT;
    if live_coefficient < inputs.match_threshold || challenge_coefficient < inputs.match_threshold {
        tracing::warn!(
            route = MatchRequest::ROUTE_ID,
            "match scored below threshold"
        );
        return Ok(Err(RejectReason::MatchBelowThreshold));
    }

    Ok(Ok(MatchStatement {
        version: STATEMENT_VERSION,
        live_image_hash,
        credential_claim,
        challenger_image_hash,
        // Only the credential-vs-live score is surfaced.
        match_coefficient: live_coefficient,
    }))
}

/// Seals `payload` to the requesting client, binding `outcome` as AAD so the host cannot
/// rewrite the cleartext class without breaking authentication.
fn seal_response(
    sealer: ResponseSealer,
    outcome: MatchOutcome,
    payload: &MatchOutcomePayload,
) -> Result<MatchResponse, EnclaveError> {
    let mut cbor = Vec::new();
    ciborium::into_writer(payload, &mut cbor).map_err(|error| {
        tracing::error!(?error, "failed to encode match response");
        EnclaveError::Internal
    })?;

    let ciphertext = sealer.seal(&cbor, &outcome.response_aad())?;

    Ok(MatchResponse {
        outcome,
        ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use enclave_types::{
        CHANNEL_VERSION, ENCAPPED_KEY_LEN, EnclaveError, MatchOutcome, MatchOutcomePayload,
        MatchRequest, MatchResponse, RejectReason,
    };
    use sha2::{Digest, Sha256};

    use super::{MatchInputs, handler};
    use crate::state::{EnclaveState, test_client::ClientChannel};

    fn cbor(inputs: &MatchInputs) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(inputs, &mut bytes).expect("cbor encoding should succeed");
        bytes
    }

    fn hashes_json_for(image: &[u8]) -> Vec<u8> {
        let hash = hex::encode(Sha256::digest(image));
        format!(r#"{{"thumbnail.png":"{hash}"}}"#).into_bytes()
    }

    fn inputs_for(credential: &[u8], match_threshold: f32) -> MatchInputs {
        MatchInputs {
            version: CHANNEL_VERSION,
            live_image: b"liveness-frame".to_vec(),
            credential_image: credential.to_vec(),
            hashes_json: hashes_json_for(credential),
            challenge_image: b"challenge-frame".to_vec(),
            match_threshold,
        }
    }

    /// Seals `plaintext` to `state` and returns the client channel plus the wire request.
    fn request_for(state: &EnclaveState, plaintext: &[u8]) -> (ClientChannel, MatchRequest) {
        let (client, body) = ClientChannel::seal(&state.transit_public_key(), plaintext);

        (client, MatchRequest { body })
    }

    /// Opens a response the way a client would, and decodes the sealed payload.
    fn open(client: &ClientChannel, response: &MatchResponse) -> MatchOutcomePayload {
        let plaintext = client
            .open_response(&response.ciphertext, &response.outcome.response_aad())
            .expect("the requesting client should be able to open the response");

        ciborium::from_reader(std::io::Cursor::new(plaintext))
            .expect("the sealed payload should be CBOR")
    }

    #[tokio::test]
    async fn round_trips_a_statement_to_the_requesting_client() {
        let state = Arc::new(EnclaveState::generate());
        let credential = b"credential-thumbnail";
        let inputs = inputs_for(credential, 0.5);
        let (client, request) = request_for(&state, &cbor(&inputs));

        let response = handler(state, request).await.expect("match should succeed");

        assert_eq!(response.outcome, MatchOutcome::Statement);
        let statement = open(&client, &response).expect("payload should hold a statement");
        assert_eq!(statement.version, 1);
        assert_eq!(
            statement.live_image_hash,
            Sha256::digest(&inputs.live_image).as_slice()
        );
        assert_eq!(
            statement.credential_claim,
            Sha256::digest(&inputs.hashes_json).as_slice()
        );
        assert_eq!(
            statement.challenger_image_hash,
            Sha256::digest(&inputs.challenge_image).as_slice()
        );
        assert_eq!(statement.match_coefficient.to_bits(), 1.0f32.to_bits());
    }

    #[tokio::test]
    async fn statement_is_absent_from_the_cleartext_response() {
        let state = Arc::new(EnclaveState::generate());
        let credential = b"credential-thumbnail";
        let inputs = inputs_for(credential, 0.5);
        let (_, request) = request_for(&state, &cbor(&inputs));

        let response = handler(state, request).await.expect("match should succeed");

        // The credential claim is the most sensitive field the host must not learn.
        let claim = Sha256::digest(&inputs.hashes_json);
        assert!(
            !response
                .ciphertext
                .windows(claim.len())
                .any(|window| window == claim.as_slice())
        );
    }

    #[tokio::test]
    async fn reject_reason_is_sealed_and_absent_from_the_clear_class() {
        let state = Arc::new(EnclaveState::generate());
        // A threshold above the dummy coefficient (1.0) forces the gate to reject.
        let inputs = inputs_for(b"credential-thumbnail", 1.5);
        let (client, request) = request_for(&state, &cbor(&inputs));

        let response = handler(state, request)
            .await
            .expect("a rejection still produces a sealed response");

        // The host sees only the coarse class...
        assert_eq!(response.outcome, MatchOutcome::Rejected);
        // ...while the reason travels sealed.
        assert_eq!(
            open(&client, &response),
            Err(RejectReason::MatchBelowThreshold)
        );
    }

    #[tokio::test]
    async fn thumbnail_mismatch_is_sealed_as_a_rejection() {
        let state = Arc::new(EnclaveState::generate());
        let mut inputs = inputs_for(b"the-enrolled-image", 0.5);
        inputs.credential_image = b"a-different-image".to_vec();
        let (client, request) = request_for(&state, &cbor(&inputs));

        let response = handler(state, request)
            .await
            .expect("should seal a rejection");

        assert_eq!(response.outcome, MatchOutcome::Rejected);
        assert_eq!(
            open(&client, &response),
            Err(RejectReason::ThumbnailHashMismatch)
        );
    }

    #[tokio::test]
    async fn a_second_channel_cannot_open_the_response() {
        let state = Arc::new(EnclaveState::generate());
        let inputs = inputs_for(b"credential-thumbnail", 0.5);
        let (_, request) = request_for(&state, &cbor(&inputs));
        // A second setup against the same transit key: a different ephemeral, so a
        // different exporter secret.
        let (eavesdropper, _) = ClientChannel::seal(&state.transit_public_key(), b"unrelated");

        let response = handler(state, request).await.expect("match should succeed");

        assert!(
            eavesdropper
                .open_response(&response.ciphertext, &response.outcome.response_aad())
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_tampered_response_ciphertext_fails_to_open() {
        let state = Arc::new(EnclaveState::generate());
        let inputs = inputs_for(b"credential-thumbnail", 0.5);
        let (client, request) = request_for(&state, &cbor(&inputs));

        let mut response = handler(state, request).await.expect("match should succeed");
        response.ciphertext[0] ^= 0x01;

        assert!(
            client
                .open_response(&response.ciphertext, &response.outcome.response_aad())
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_rewritten_outcome_class_fails_to_open() {
        let state = Arc::new(EnclaveState::generate());
        let inputs = inputs_for(b"credential-thumbnail", 0.5);
        let (client, request) = request_for(&state, &cbor(&inputs));

        let response = handler(state, request).await.expect("match should succeed");

        // A host that downgrades a statement to a rejection changes the AAD.
        assert_eq!(response.outcome, MatchOutcome::Statement);
        assert!(
            client
                .open_response(&response.ciphertext, &MatchOutcome::Rejected.response_aad())
                .is_none()
        );
    }

    #[tokio::test]
    async fn rejects_an_unopenable_request() {
        let state = Arc::new(EnclaveState::generate());
        let inputs = inputs_for(b"credential-thumbnail", 0.5);
        let (_, mut request) = request_for(&state, &cbor(&inputs));
        request.body[..ENCAPPED_KEY_LEN].fill(0);

        let result = handler(state, request).await;

        assert_eq!(result.err(), Some(EnclaveError::BadRequest));
    }

    #[tokio::test]
    async fn rejects_non_cbor_plaintext() {
        let state = Arc::new(EnclaveState::generate());
        let (_, request) = request_for(&state, b"not cbor framing");

        let result = handler(state, request).await;

        assert_eq!(result.err(), Some(EnclaveError::BadRequest));
    }

    #[tokio::test]
    async fn rejects_an_unsupported_payload_version() {
        let state = Arc::new(EnclaveState::generate());
        let mut inputs = inputs_for(b"credential-thumbnail", 0.5);
        inputs.version = CHANNEL_VERSION + 1;
        let (_, request) = request_for(&state, &cbor(&inputs));

        let result = handler(state, request).await;

        assert_eq!(result.err(), Some(EnclaveError::BadRequest));
    }

    #[tokio::test]
    async fn keeps_malformed_hashes_json_in_the_clear() {
        let state = Arc::new(EnclaveState::generate());
        let mut inputs = inputs_for(b"credential-thumbnail", 0.5);
        inputs.hashes_json = b"not valid json".to_vec();
        let (_, request) = request_for(&state, &cbor(&inputs));

        let result = handler(state, request).await;

        // A caller mistake, not a statement about a face: no channel detail needed.
        assert_eq!(result.err(), Some(EnclaveError::BadRequest));
    }
}

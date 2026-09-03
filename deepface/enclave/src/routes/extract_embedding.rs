use std::sync::Arc;

use attested_channel::channel::{SealedRequest, SealedResponse, UnwrapErr};
use deepface_enclave_types::{EnclaveError, ExtractEmbeddingRequest, ExtractEmbeddingResponse};
use deepface_protocol::Error as ProtocolError;
use deepface_protocol::embedding::{
    EmbeddingExtractionFailureReason, ExtractEmbeddingInputs, ExtractEmbeddingResult,
};
use getrandom::SysRng;
use pontifex::Request;

use crate::state::EnclaveState;

/// Extracts an enrollment embedding from one image.
///
/// Everything learned after opening the request is sealed back to the requester. The host sees an
/// error only when no response channel exists or the enclave itself faults.
///
/// # Errors
///
/// Returns [`EnclaveError`] if the request cannot be opened or the response cannot be sealed.
pub async fn handler(
    state: Arc<EnclaveState>,
    request: ExtractEmbeddingRequest,
) -> Result<ExtractEmbeddingResponse, EnclaveError> {
    let (plaintext, sealer) = state
        .responder()
        .open(&SealedRequest::from_bytes(request.body))
        .map_err(|error| {
            tracing::warn!(
                ?error,
                route = ExtractEmbeddingRequest::ROUTE_ID,
                "failed to open sealed request"
            );
            EnclaveError::RequestNotOpened
        })?;

    let result = run(&state, &plaintext)?;
    let encoded = result.to_cbor().map_err(|error| {
        tracing::error!(?error, "failed to encode the embedding extraction result");
        EnclaveError::Internal
    })?;
    let ciphertext = sealer
        .seal(&encoded, &mut UnwrapErr(SysRng))
        .map_err(|error| {
            tracing::error!(?error, "failed to seal the embedding extraction response");
            EnclaveError::Internal
        })?;

    Ok(ExtractEmbeddingResponse {
        ciphertext: SealedResponse::into_bytes(ciphertext),
    })
}

/// Decodes the opened plaintext and extracts its image's embedding.
fn run(state: &EnclaveState, plaintext: &[u8]) -> Result<ExtractEmbeddingResult, EnclaveError> {
    let inputs = match ExtractEmbeddingInputs::from_cbor(plaintext) {
        Ok(inputs) => inputs,
        Err(error) => {
            tracing::warn!(
                ?error,
                route = ExtractEmbeddingRequest::ROUTE_ID,
                "unusable embedding extraction payload"
            );
            return match error {
                ProtocolError::Malformed => Ok(ExtractEmbeddingResult::Failed(
                    EmbeddingExtractionFailureReason::MalformedInputs,
                )),
                ProtocolError::UnsupportedChannelVersion => Ok(ExtractEmbeddingResult::Failed(
                    EmbeddingExtractionFailureReason::UnsupportedVersion,
                )),
                _ => Err(EnclaveError::Internal),
            };
        }
    };

    Ok(match state.face_engine().extract_embedding(&inputs.image) {
        Ok(embedding) => ExtractEmbeddingResult::Success(embedding),
        Err(reason) => ExtractEmbeddingResult::Failed(reason),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use attested_channel::channel::{
        CHANNEL_VERSION, Requester, ResponseOpener, SealedResponse, UnwrapErr,
    };
    use deepface_enclave_types::{EnclaveError, ExtractEmbeddingRequest};
    use deepface_protocol::{
        embedding::{
            Embedding, EmbeddingExtractionFailureReason, ExtractEmbeddingInputs,
            ExtractEmbeddingResult,
        },
        messages::FailureReason,
    };
    use getrandom::SysRng;

    use super::handler;
    use crate::{
        face_engine::{ComparisonScores, FaceProcessor},
        state::EnclaveState,
        test_support::EchoAttestor,
    };

    const IMAGE: &[u8] = b"enrollment-image";

    struct MockFaceEngine {
        result: Result<Embedding, EmbeddingExtractionFailureReason>,
    }

    impl FaceProcessor for MockFaceEngine {
        fn extract_embedding(
            &self,
            image: &[u8],
        ) -> Result<Embedding, EmbeddingExtractionFailureReason> {
            assert_eq!(image, IMAGE);
            self.result.clone()
        }

        fn compare_reference_to_probes(
            &self,
            _credential_image: &[u8],
            _live_image: &[u8],
            _challenge_image: &[u8],
        ) -> Result<ComparisonScores, FailureReason> {
            panic!("extraction test unexpectedly compared embeddings")
        }
    }

    fn embedding() -> Embedding {
        Embedding {
            vector: "ZmFrZS12ZWN0b3I=".to_owned(),
            embedding_type: "ghostfacenet_flipped_mean".to_owned(),
            embedding_version: "2.0.0".to_owned(),
            embedding_inference_backend: "face-engine".to_owned(),
        }
    }

    fn state_with(
        result: Result<Embedding, EmbeddingExtractionFailureReason>,
    ) -> Arc<EnclaveState> {
        Arc::new(
            EnclaveState::generate(Arc::new(EchoAttestor), Arc::new(MockFaceEngine { result }))
                .expect("boot state should generate"),
        )
    }

    fn request_for(
        state: &EnclaveState,
        inputs: &ExtractEmbeddingInputs,
    ) -> (ResponseOpener, ExtractEmbeddingRequest) {
        let requester = Requester::new(state.encryption_public_key()).expect("valid key");
        let plaintext = inputs.to_cbor().expect("encoding should succeed");
        let (sealed, opener) = requester
            .seal(&plaintext, &mut UnwrapErr(SysRng))
            .expect("sealing should succeed");

        (
            opener,
            ExtractEmbeddingRequest {
                body: sealed.into_bytes(),
            },
        )
    }

    fn inputs() -> ExtractEmbeddingInputs {
        ExtractEmbeddingInputs {
            version: CHANNEL_VERSION,
            image: IMAGE.to_vec(),
        }
    }

    async fn open_result(
        state: Arc<EnclaveState>,
        inputs: &ExtractEmbeddingInputs,
    ) -> ExtractEmbeddingResult {
        let (opener, request) = request_for(&state, inputs);
        let response = handler(state, request).await.expect("should answer");
        let plaintext = opener
            .open(&SealedResponse::from_bytes(response.ciphertext))
            .expect("requester should open its response");
        ExtractEmbeddingResult::from_cbor(&plaintext).expect("result should decode")
    }

    #[tokio::test]
    async fn seals_the_extracted_embedding_to_the_requester() {
        let expected = embedding();
        let result = open_result(state_with(Ok(expected.clone())), &inputs()).await;

        assert_eq!(result, ExtractEmbeddingResult::Success(expected));
    }

    #[tokio::test]
    async fn an_image_failure_is_a_sealed_failure() {
        let result = open_result(
            state_with(Err(EmbeddingExtractionFailureReason::ImageAnalysisFailed)),
            &inputs(),
        )
        .await;

        assert_eq!(
            result,
            ExtractEmbeddingResult::Failed(EmbeddingExtractionFailureReason::ImageAnalysisFailed)
        );
    }

    #[tokio::test]
    async fn malformed_and_unsupported_inputs_are_sealed_failures() {
        let state = state_with(Err(EmbeddingExtractionFailureReason::ImageAnalysisFailed));
        let requester = Requester::new(state.encryption_public_key()).expect("valid key");
        let (sealed, opener) = requester
            .seal(b"not cbor", &mut UnwrapErr(SysRng))
            .expect("should seal");
        let response = handler(
            Arc::clone(&state),
            ExtractEmbeddingRequest {
                body: sealed.into_bytes(),
            },
        )
        .await
        .expect("should answer malformed plaintext");
        let plaintext = opener
            .open(&SealedResponse::from_bytes(response.ciphertext))
            .expect("should open");
        assert_eq!(
            ExtractEmbeddingResult::from_cbor(&plaintext).expect("should decode"),
            ExtractEmbeddingResult::Failed(EmbeddingExtractionFailureReason::MalformedInputs)
        );

        let unsupported = ExtractEmbeddingInputs {
            version: CHANNEL_VERSION + 1,
            image: IMAGE.to_vec(),
        };
        assert_eq!(
            open_result(state, &unsupported).await,
            ExtractEmbeddingResult::Failed(EmbeddingExtractionFailureReason::UnsupportedVersion)
        );
    }

    #[tokio::test]
    async fn rejects_a_request_sealed_to_another_boot() {
        let state = state_with(Ok(embedding()));
        let other = state_with(Ok(embedding()));
        let (_, request) = request_for(&other, &inputs());

        assert_eq!(
            handler(state, request).await.err(),
            Some(EnclaveError::RequestNotOpened)
        );
    }
}

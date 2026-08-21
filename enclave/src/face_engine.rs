//! Face Engine initialization and in-enclave embedding comparison.

use std::{io::Cursor, sync::Arc};

use deepface_protocol::messages::FailureReason;
use face_engine::{
    components::{
        captured_image_analyzer::CapturedImageAnalyzer, template_generator::TemplateGenerator,
    },
    io::rgb_image::RgbImage,
    matchers::cosine_similarity::CosineSimilarity,
    nodes::{subject_extraction::SubjectFace, template_generation::EmbeddingVector},
};
use image::ImageReader;

const FACE_ANALYZER_CONFIG: &str = include_str!("../config/face_analyzer.yaml");
const FACE_TEMPLATE_GENERATOR_CONFIG: &str = include_str!("../config/face_template_generator.yaml");

// TODO: Inject production Face Engine configs and model artifacts at runtime instead of compiling
// the prototype configs and fixed `/models` paths into the enclave.
/// Similarity scores for one credential image against the live and challenge images.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ComparisonScores {
    /// Credential-to-live cosine similarity.
    pub live_similarity: f32,
    /// Credential-to-challenge cosine similarity.
    pub challenge_similarity: f32,
}

/// Face comparison behavior required by the enclave match operation.
pub trait FaceComparator: Send + Sync {
    /// Generates one credential embedding and compares it with the live and challenge images.
    ///
    /// # Errors
    ///
    /// Returns a structured enclave error when an image is invalid, embedding generation fails,
    /// or the embeddings cannot be compared.
    fn compare_reference_to_probes(
        &self,
        credential_image: &[u8],
        live_image: &[u8],
        challenge_image: &[u8],
    ) -> Result<ComparisonScores, FailureReason>;
}

/// Face Engine implementation backed by the configured ONNX models.
pub struct FaceEngine {
    template_generator: TemplateGenerator,
    analyzer: CapturedImageAnalyzer,
    matcher: CosineSimilarity,
}

impl Default for FaceEngine {
    fn default() -> Self {
        Self {
            template_generator: TemplateGenerator::new(FACE_TEMPLATE_GENERATOR_CONFIG)
                .expect("built-in Face Engine template generator config and model should load"),
            analyzer: CapturedImageAnalyzer::new(FACE_ANALYZER_CONFIG)
                .expect("built-in Face Engine analyzer config and model should load"),
            matcher: CosineSimilarity::default(),
        }
    }
}

impl FaceEngine {
    fn generate_embedding(&self, image_bytes: &[u8]) -> Result<EmbeddingVector, FailureReason> {
        let dynamic_image = ImageReader::new(Cursor::new(image_bytes))
            .with_guessed_format()
            .map_err(|error| {
                tracing::warn!(%error, "could not determine image format");
                FailureReason::ImageAnalysisFailed
            })?
            .decode()
            .map_err(|error| {
                tracing::warn!(%error, "could not decode face image");
                FailureReason::ImageAnalysisFailed
            })?;

        let rgb_image = RgbImage::new(
            dynamic_image.to_rgb8().into_vec(),
            dynamic_image.height(),
            dynamic_image.width(),
            None,
        )
        .map_err(|error| {
            tracing::warn!(%error, "could not construct Face Engine RGB image");
            FailureReason::ImageAnalysisFailed
        })?;

        let analysis = self
            .analyzer
            .run_inference_rgb(&rgb_image)
            .map_err(|error| {
                tracing::error!(%error, "Face Engine image analysis failed");
                FailureReason::ImageAnalysisFailed
            })?;
        if let Some(error) = analysis.error {
            tracing::warn!(?error, "Face Engine image analysis failed");
            return Err(FailureReason::ImageAnalysisFailed);
        }

        let subject_metadata = analysis.subject_face_extracted.ok_or_else(|| {
            tracing::warn!("Face Engine did not extract a subject");
            FailureReason::ImageAnalysisFailed
        })?;
        let subject = SubjectFace {
            input_image: Arc::new(rgb_image),
            metadata: subject_metadata,
        };

        let output = self
            .template_generator
            .run_inference(&subject)
            .map_err(|error| {
                tracing::error!(%error, "Face Engine template inference failed");
                FailureReason::ImageAnalysisFailed
            })?;

        if let Some(error) = output.metadata.error {
            tracing::warn!(?error, "Face Engine rejected the generated template");
            return Err(FailureReason::ImageAnalysisFailed);
        }

        output.embedding_vector.ok_or_else(|| {
            tracing::error!("Face Engine returned no embedding");
            FailureReason::ImageAnalysisFailed
        })
    }

    fn compute_score(
        &self,
        probe: &EmbeddingVector,
        reference: &EmbeddingVector,
    ) -> Result<f32, FailureReason> {
        self.matcher
            .compute_score(probe, reference)
            .map_err(|error| {
                tracing::error!(%error, "Face Engine embedding comparison failed");
                FailureReason::ImageAnalysisFailed
            })
    }
}

impl FaceComparator for FaceEngine {
    fn compare_reference_to_probes(
        &self,
        credential_image: &[u8],
        live_image: &[u8],
        challenge_image: &[u8],
    ) -> Result<ComparisonScores, FailureReason> {
        let reference = self.generate_embedding(credential_image)?;
        let live = self.generate_embedding(live_image)?;
        let challenge = self.generate_embedding(challenge_image)?;

        let live_similarity = self.compute_score(&live, &reference)?;
        let challenge_similarity = self.compute_score(&challenge, &reference)?;

        Ok(ComparisonScores {
            live_similarity,
            challenge_similarity,
        })
    }
}

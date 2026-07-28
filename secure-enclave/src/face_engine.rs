//! Face Engine initialization and in-enclave embedding comparison.

use std::{
    io::Cursor,
    sync::{Arc, OnceLock},
};

use enclave_types::{CompareFacesResponse, EnclaveError};
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
const SIMILARITY_THRESHOLD: f32 = 0.46;

static FACE_ENGINE: OnceLock<FaceEngine> = OnceLock::new();

// TODO: Inject production Face Engine configs and model artifacts at runtime instead of compiling
// the prototype configs and fixed `/models` paths into the enclave.
struct FaceEngine {
    template_generator: TemplateGenerator,
    analyzer: CapturedImageAnalyzer,
    matcher: CosineSimilarity,
    similarity_threshold: f32,
}

impl Default for FaceEngine {
    fn default() -> Self {
        Self {
            template_generator: TemplateGenerator::new(FACE_TEMPLATE_GENERATOR_CONFIG)
                .expect("built-in Face Engine template generator config and model should load"),
            analyzer: CapturedImageAnalyzer::new(FACE_ANALYZER_CONFIG)
                .expect("built-in Face Engine analyzer config and model should load"),
            matcher: CosineSimilarity::default(),
            similarity_threshold: SIMILARITY_THRESHOLD,
        }
    }
}

impl FaceEngine {
    fn generate_embedding(&self, image_bytes: Vec<u8>) -> Result<EmbeddingVector, EnclaveError> {
        let dynamic_image = ImageReader::new(Cursor::new(image_bytes))
            .with_guessed_format()
            .map_err(|error| {
                tracing::warn!(%error, "could not determine image format");
                EnclaveError::InvalidImage
            })?
            .decode()
            .map_err(|error| {
                tracing::warn!(%error, "could not decode face image");
                EnclaveError::InvalidImage
            })?;

        let rgb_image = RgbImage::new(
            dynamic_image.to_rgb8().into_vec(),
            dynamic_image.height(),
            dynamic_image.width(),
            None,
        )
        .map_err(|error| {
            tracing::warn!(%error, "could not construct Face Engine RGB image");
            EnclaveError::InvalidImage
        })?;

        let analysis = self
            .analyzer
            .run_inference_rgb(&rgb_image)
            .map_err(|error| {
                tracing::error!(%error, "Face Engine image analysis failed");
                EnclaveError::EmbeddingGenerationFailed
            })?;
        if let Some(error) = analysis.error {
            tracing::warn!(?error, "Face Engine image analysis failed");
            return Err(EnclaveError::EmbeddingGenerationFailed);
        }

        let subject_metadata = analysis.subject_face_extracted.ok_or_else(|| {
            tracing::warn!("Face Engine did not extract a subject");
            EnclaveError::EmbeddingGenerationFailed
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
                EnclaveError::EmbeddingGenerationFailed
            })?;

        if let Some(error) = output.metadata.error {
            tracing::warn!(?error, "Face Engine rejected the generated template");
            return Err(EnclaveError::EmbeddingGenerationFailed);
        }

        output.embedding_vector.ok_or_else(|| {
            tracing::error!("Face Engine returned no embedding");
            EnclaveError::EmbeddingGenerationFailed
        })
    }

    fn compare(
        &self,
        reference_image: Vec<u8>,
        probe_image: Vec<u8>,
    ) -> Result<CompareFacesResponse, EnclaveError> {
        let reference = self.generate_embedding(reference_image)?;
        let probe = self.generate_embedding(probe_image)?;
        let similarity = self
            .matcher
            .compute_score(&probe, &reference)
            .map_err(|error| {
                tracing::error!(%error, "Face Engine embedding comparison failed");
                EnclaveError::EmbeddingComparisonFailed
            })?;

        Ok(CompareFacesResponse {
            similarity,
            matches: similarity >= self.similarity_threshold,
        })
    }
}

/// Initializes the process-global Face Engine with its built-in prototype configuration.
///
/// # Errors
///
/// Returns an error when Face Engine was already initialized.
pub fn initialize() -> anyhow::Result<()> {
    let engine = FaceEngine::default();
    FACE_ENGINE
        .set(engine)
        .map_err(|_| anyhow::anyhow!("Face Engine is already initialized"))?;
    tracing::info!("initialized Face Engine");
    Ok(())
}

/// Generates both face embeddings inside the enclave and compares them.
///
/// # Errors
///
/// Returns a structured enclave error when an image is invalid, embedding generation fails, or
/// the embeddings cannot be compared.
pub fn compare(
    reference_image: Vec<u8>,
    probe_image: Vec<u8>,
) -> Result<CompareFacesResponse, EnclaveError> {
    FACE_ENGINE
        .get()
        .ok_or(EnclaveError::NotReady)?
        .compare(reference_image, probe_image)
}

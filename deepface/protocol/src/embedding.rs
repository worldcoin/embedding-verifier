//! Sealed messages for extracting an enrollment embedding from one image.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::Error;

/// The sealed input to one embedding extraction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractEmbeddingInputs {
    /// Channel version the requester believes it is speaking.
    pub version: u8,
    /// Raw bytes of the image from which to extract an embedding.
    #[serde(with = "serde_bytes")]
    pub image: Vec<u8>,
}

impl ExtractEmbeddingInputs {
    /// Encodes the inputs as CBOR. [`Zeroizing`] because it holds a biometric image.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encoding`] if CBOR encoding fails.
    pub fn to_cbor(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut encoded = Vec::new();
        ciborium::into_writer(self, &mut encoded).map_err(|_| Error::Encoding)?;

        Ok(Zeroizing::new(encoded))
    }

    /// Decodes the inputs and checks the declared channel version.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] if the bytes are not this framing, or
    /// [`Error::UnsupportedChannelVersion`] if `version` is unsupported.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let inputs: Self = ciborium::from_reader(bytes).map_err(|_| Error::Malformed)?;

        if inputs.version == attested_channel::channel::CHANNEL_VERSION {
            Ok(inputs)
        } else {
            Err(Error::UnsupportedChannelVersion)
        }
    }
}

/// A Face Engine embedding suitable for enrollment and later comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Embedding {
    /// Base64-encoded floating-point vector in the Face Engine representation.
    pub vector: String,
    /// Model backbone that generated the embedding.
    pub embedding_type: String,
    /// Semantic version of the embedding format.
    pub embedding_version: String,
    /// Inference backend that generated the embedding.
    pub embedding_inference_backend: String,
}

/// The authoritative, sealed outcome of embedding extraction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtractEmbeddingResult {
    /// Extraction succeeded.
    Success(Embedding),
    /// No embedding was produced.
    Failed(EmbeddingExtractionFailureReason),
}

impl ExtractEmbeddingResult {
    /// Encodes the result as CBOR.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encoding`] if CBOR encoding fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut encoded = Vec::new();
        ciborium::into_writer(self, &mut encoded).map_err(|_| Error::Encoding)?;

        Ok(encoded)
    }

    /// Decodes a result.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] if the bytes are not this framing.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes).map_err(|_| Error::Malformed)
    }
}

/// Why an extraction produced no embedding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmbeddingExtractionFailureReason {
    /// The plaintext was not the CBOR framing [`ExtractEmbeddingInputs`] writes.
    MalformedInputs,
    /// The inputs declared a channel version the enclave does not implement.
    UnsupportedVersion,
    /// The image could not be decoded, analyzed, or converted into an embedding.
    ImageAnalysisFailed,
}

#[cfg(test)]
mod tests {
    use attested_channel::channel::CHANNEL_VERSION;

    use super::{
        Embedding, EmbeddingExtractionFailureReason, ExtractEmbeddingInputs, ExtractEmbeddingResult,
    };
    use crate::Error;

    fn embedding() -> Embedding {
        Embedding {
            vector: "ZmFrZS12ZWN0b3I=".to_owned(),
            embedding_type: "ghostfacenet_flipped_mean".to_owned(),
            embedding_version: "2.0.0".to_owned(),
            embedding_inference_backend: "face-engine".to_owned(),
        }
    }

    #[test]
    fn inputs_round_trip_and_reject_an_unsupported_version() {
        let inputs = ExtractEmbeddingInputs {
            version: CHANNEL_VERSION,
            image: b"image".to_vec(),
        };
        let encoded = inputs.to_cbor().expect("should encode");
        assert_eq!(
            ExtractEmbeddingInputs::from_cbor(&encoded).expect("should decode"),
            inputs
        );

        let unsupported = ExtractEmbeddingInputs {
            version: CHANNEL_VERSION + 1,
            image: b"image".to_vec(),
        };
        assert_eq!(
            ExtractEmbeddingInputs::from_cbor(&unsupported.to_cbor().expect("should encode")),
            Err(Error::UnsupportedChannelVersion)
        );
    }

    #[test]
    fn results_round_trip() {
        for result in [
            ExtractEmbeddingResult::Success(embedding()),
            ExtractEmbeddingResult::Failed(EmbeddingExtractionFailureReason::ImageAnalysisFailed),
        ] {
            let encoded = result.to_cbor().expect("should encode");
            assert_eq!(
                ExtractEmbeddingResult::from_cbor(&encoded).expect("should decode"),
                result
            );
        }
    }
}

use serde::{Deserialize, Serialize};

/// Errors returned by enclave operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnclaveError {
    /// The enclave is reachable but not ready to process requests.
    NotReady,
    /// The Nitro Secure Module is unavailable.
    SecureModuleNotInitialized,
    /// The Nitro Secure Module could not produce an attestation document.
    AttestationFailed,
    /// The sealed request could not be opened with the enclave encryption key.
    DecryptFailed,
    /// The decrypted match payload was not valid CBOR framing.
    MalformedMatchPayload,
    /// hashes.json was absent, not valid JSON, missing the `thumbnail.png` entry, or the
    /// committed thumbnail hash was malformed.
    InvalidHashesJson,
    /// The credential image did not hash to the `thumbnail.png` value committed in
    /// hashes.json.
    ThumbnailHashMismatch,
    /// A comparison scored below the RP-supplied `match_threshold`.
    MatchBelowThreshold,
    /// An input could not be decoded as a supported image.
    InvalidImage,
    /// Face Engine could not generate an embedding for an input image.
    EmbeddingGenerationFailed,
    /// Face Engine could not compare the generated embeddings.
    EmbeddingComparisonFailed,
}

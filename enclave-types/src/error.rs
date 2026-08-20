use serde::{Deserialize, Serialize};

/// Errors returned by enclave operations.
///
/// Coarse on the match path: detail worth disclosing travels sealed in the response ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnclaveError {
    /// The enclave is reachable but not ready to process requests.
    NotReady,
    /// The Nitro Secure Module is unavailable.
    SecureModuleNotInitialized,
    /// The Nitro Secure Module could not produce an attestation document.
    AttestationFailed,
    /// The sealed request could not be opened, or its plaintext was unusable. Merged because a
    /// request that cannot be opened has no channel to carry detail back through.
    BadRequest,
    /// The challenge image did not decrypt. Separate from [`Self::BadRequest`] because the
    /// ciphertext came from the *host*.
    ChallengeDecryptFailed,
    /// The Face Engine rejected an image on quality grounds. In the clear because it describes the
    /// photograph, not the person. The match verdict never travels this way.
    ImageAnalysisFailed,
    /// The enclave failed while producing a response. Detail stays in the enclave log.
    Internal,
}

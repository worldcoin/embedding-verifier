use serde::{Deserialize, Serialize};

/// Errors returned by enclave operations.
///
/// Deliberately coarse on the match path: detail worth disclosing travels sealed inside the
/// response ciphertext instead. What remains is what an untrusted host needs to pick a status code,
/// decide whether to retry, and count failures by class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnclaveError {
    /// The enclave is reachable but not ready to process requests.
    NotReady,
    /// The Nitro Secure Module is unavailable.
    SecureModuleNotInitialized,
    /// The Nitro Secure Module could not produce an attestation document.
    AttestationFailed,
    /// The sealed request could not be opened, or its plaintext was unusable.
    ///
    /// Covers a rejected encapsulated key, a failed AEAD open, non-CBOR framing, an unsupported
    /// channel version, and a malformed `hashes.json`. Merged because a request that cannot be
    /// opened has no channel to carry detail back through.
    BadRequest,
    /// The challenge image did not decrypt under the key sealed in the request.
    ///
    /// Separate from [`Self::BadRequest`] because the ciphertext came from the *host*, so a fetch
    /// problem does not read as a client error.
    ChallengeDecryptFailed,
    /// The Face Engine rejected an image on quality grounds.
    ///
    /// In the clear because it describes the photograph, not the person, and the client has to know
    /// to retake it. The match verdict never travels this way.
    ImageAnalysisFailed,
    /// The enclave failed while producing a response. Detail stays in the enclave log.
    Internal,
}

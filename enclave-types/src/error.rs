use serde::{Deserialize, Serialize};

/// Errors returned by enclave operations.
///
/// Everything on the match path is deliberately **coarse**. Once a request has been opened there
/// is a sealed channel back to the requester, so any detail worth disclosing travels inside the
/// response ciphertext instead. What remains here is only what an untrusted host legitimately
/// needs in order to pick a status code, decide whether to retry, and count failures by class.
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
    /// channel version, and a malformed `hashes.json`. Deliberately merged: a request that cannot
    /// be opened has no channel to carry detail back through, and the remaining cases are not
    /// worth distinguishing to a host that must not learn them.
    BadRequest,
    /// The challenge image did not decrypt under the key sealed in the request.
    ///
    /// Distinct from [`Self::BadRequest`] because it is the one input the *host* supplied, so
    /// attributing it separately keeps a host-side fetch problem from reading as a client error.
    ChallengeDecryptFailed,
    /// The Face Engine rejected an image on quality grounds.
    ///
    /// Surfaced in the clear because it describes the photograph rather than the person: a client
    /// has to know to retake it. The match verdict itself never travels this way.
    ImageAnalysisFailed,
    /// The enclave failed while producing a response. Detail stays in the enclave log.
    Internal,
}

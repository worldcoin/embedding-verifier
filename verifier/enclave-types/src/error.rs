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
    /// The sealed request could not be opened.
    ///
    /// The only input failure the host may see: with no channel there is nothing to seal a reply
    /// into. Everything the enclave learns *after* opening travels sealed instead.
    RequestNotOpened,
    /// The enclave failed while producing a response. Detail stays in the enclave log.
    Internal,
}

/// Why a sealed match payload could not be encoded or decoded. Client-local only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingError {
    /// The bytes were not the CBOR framing [`crate::MatchInputs`] and [`crate::MatchResult`] write.
    Malformed,
    /// CBOR encoding failed.
    Encoding,
    /// An encoded match result exceeded its fixed sealed-response envelope.
    ResponseTooLarge,
    /// Match inputs declared a channel version this build does not implement.
    UnsupportedChannelVersion,
}

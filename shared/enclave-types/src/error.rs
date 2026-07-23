use serde::{Deserialize, Serialize};

/// Errors returned by secure-enclave operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnclaveError {
    /// The enclave is reachable but not ready to process requests.
    NotReady,
    /// The Nitro Secure Module is unavailable.
    SecureModuleNotInitialized,
    /// The Nitro Secure Module could not produce an attestation document.
    AttestationFailed,
    /// The sealed request could not be decrypted with the enclave transit key.
    DecryptFailed,
    /// The decrypted payload was not valid CBOR framing.
    MalformedPcpPayload,
    /// hashes.json was absent, not valid JSON, missing the `thumbnail.png` entry, or the
    /// committed thumbnail hash was malformed.
    InvalidHashesJson,
    /// The credential image did not match the committed `thumbnail.png` hash.
    ThumbnailHashMismatch,
    /// A comparison scored below the RP-supplied `match_threshold`. Returned instead
    /// of a statement so the caller avoids a circuit computation that would fail its
    /// constraints; the authoritative check still happens in-circuit.
    MatchBelowThreshold,
}

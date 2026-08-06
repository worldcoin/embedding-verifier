use serde::{Deserialize, Serialize};

/// Errors returned by secure-enclave operations.
///
/// Everything reachable on the match path is deliberately **coarse**. Once a request has
/// been opened there is a secure channel back to the client, so any detail worth
/// disclosing travels sealed inside
/// [`MatchResponse::ciphertext`](crate::MatchResponse::ciphertext) as a
/// [`RejectReason`](crate::RejectReason); what remains here is only what the host
/// legitimately needs to pick a status code, retry, and count failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnclaveError {
    /// The enclave is reachable but not ready to process requests.
    NotReady,
    /// The Nitro Secure Module is unavailable. Transit-key path only.
    SecureModuleNotInitialized,
    /// The Nitro Secure Module could not produce an attestation document. Transit-key
    /// path only.
    AttestationFailed,
    /// The request could not be opened, or its plaintext was not usable.
    ///
    /// Covers a rejected encapsulated key, a failed AEAD open, non-CBOR framing, an
    /// unsupported channel version, and a malformed `hashes.json`. Deliberately merged:
    /// an unopenable request has no channel to carry detail into, and the cases that do
    /// have one are not worth distinguishing to an untrusted host.
    BadRequest,
    /// The enclave failed while producing a response — for example the response could
    /// not be sealed. Detail stays in the enclave log.
    Internal,
}

//! Types for AWS Nitro Enclave attestation verification.
//!
//! Ported from `worldcoin/bedrock` (`bedrock/src/nitro_enclave/types.rs`), MIT © Tools for
//! Humanity. Variant names are kept so the two can be diffed.
//!
//! Licence and copyright notice: see `attested-channel/NOTICE`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Errors that can occur during enclave attestation verification.
#[derive(Debug, thiserror::Error)]
pub enum EnclaveAttestationError {
    /// Failed to parse the attestation document.
    #[error("failed to parse attestation document: {0}")]
    AttestationDocumentParseError(String),

    /// Certificate chain validation failed.
    #[error("certificate chain validation failed: {0}")]
    AttestationChainInvalid(String),

    /// COSE signature verification failed.
    #[error("signature verification failed: {0}")]
    AttestationSignatureInvalid(String),

    /// The measurements did not match any allowed configuration.
    #[error("enclave code not trusted: {0}")]
    CodeUntrusted(String),

    /// Every PCR was zero, which means a `--debug-mode` enclave whose memory the parent
    /// instance can read.
    #[error("attestation reports zeroed measurements, which means a debug-mode enclave")]
    DebugMeasurements,

    /// The attestation document is older than the caller allows.
    #[error("attestation is too old: {age_millis}ms (max: {max_age}ms)")]
    AttestationStale {
        /// Observed age in milliseconds.
        age_millis: u64,
        /// Configured maximum age in milliseconds.
        max_age: u64,
    },

    /// The attestation timestamp could not be interpreted.
    #[error("invalid timestamp: {0}")]
    AttestationInvalidTimestamp(String),

    /// The attested public key was absent or the wrong shape.
    #[error("invalid enclave public key: {0}")]
    InvalidEnclavePublicKey(String),
}

/// Result type for enclave attestation operations.
pub type EnclaveAttestationResult<T, E = EnclaveAttestationError> = Result<T, E>;

/// One expected PCR measurement. Serializes with the value as hex.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcrMeasurement {
    /// Index of the PCR measurement.
    pub index: u32,
    /// Expected value.
    #[serde(with = "hex::serde")]
    pub value: Vec<u8>,
}

impl PcrMeasurement {
    /// Creates a new [`PcrMeasurement`].
    #[must_use]
    pub fn new(index: u32, value: impl Into<Vec<u8>>) -> Self {
        Self {
            index,
            value: value.into(),
        }
    }
}

/// An attestation document whose signature, chain and measurements have all been verified.
///
/// Every field is read from the signed document, so nothing depends on the untrusted host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAttestation {
    /// The attested public key.
    pub enclave_public_key: Vec<u8>,
    /// NSM module id, e.g. `i-0abc…-enc0123…`. Identifies the enclave for one boot.
    pub module_id: String,
    /// When the document was produced, in milliseconds since the Unix epoch.
    pub timestamp_millis: u64,
    /// Every PCR the document carried.
    pub pcrs: BTreeMap<usize, Vec<u8>>,
}

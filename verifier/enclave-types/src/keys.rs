use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::Error;

/// One NSM attestation document, for whichever key was asked for.
///
/// An attestation carries a single `public_key` field, so each key needs its own document. Both are
/// public and relay unsealed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyAttestation {
    /// Raw COSE-encoded document.
    #[serde(with = "serde_bytes")]
    pub document: Vec<u8>,
}

/// Requests the attestation for this boot's encryption key.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetEncryptionKeyRequest;

impl Request for GetEncryptionKeyRequest {
    const ROUTE_ID: &'static str = "/v1/encryption-key";
    type Response = Result<KeyAttestation, Error>;
}

#[cfg(test)]
mod tests {
    use pontifex::Request;

    use super::GetEncryptionKeyRequest;

    #[test]
    fn the_encryption_key_route_id_is_versioned_and_stable() {
        assert_eq!(GetEncryptionKeyRequest::ROUTE_ID, "/v1/encryption-key");
    }
}

//! PCP binding: transport-free verification of a credential image against the
//! `thumbnail.png` hash committed in its PCP `hashes.json`.
//!
//! This module performs **no** orb-attestation signature verification and makes
//! **no** provenance claim. It checks internal consistency only — that the provided
//! image hashes to the value the accompanying `hashes.json` commits — and derives
//! `credential_claim = SHA256(hashes.json)`. That claim is a commitment, not a proof
//! of genuine Orb enrollment: a caller can trivially fabricate a self-consistent
//! `{image, hashes.json}` pair. Anti-forgery is enforced downstream by binding the
//! `credential_claim` to an issuer-signed, registry-included credential inside the
//! ZK circuit, which is out of scope for this enclave.

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Why a PCP binding check did not pass.
///
/// Kept separate from the wire errors so the caller decides what the client is told:
/// a malformed `hashes.json` is a caller mistake and stays in the clear, while a
/// thumbnail mismatch says *why a face failed* and is only ever sent sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PcpError {
    /// hashes.json was absent, not valid JSON, missing the `thumbnail.png` entry, or the
    /// committed thumbnail hash was malformed.
    InvalidHashesJson,
    /// The credential image did not match the committed `thumbnail.png` hash.
    ThumbnailHashMismatch,
}

/// Subset of `hashes.json` we consume — the committed thumbnail hash.
#[derive(Deserialize)]
struct HashesJson {
    #[serde(rename = "thumbnail.png")]
    thumbnail_png: String,
}

/// Binds `credential_image` to the `thumbnail.png` hash committed in `hashes_json`
/// and returns `credential_claim = SHA256(hashes_json)`.
///
/// Fail-closed: any parse, decode, length, or mismatch error returns an `Err` and no
/// claim. The claim is computed over the raw `hashes_json` bytes but returned only
/// after the binding check passes.
pub(crate) fn verify_pcp(
    credential_image: &[u8],
    hashes_json: &[u8],
) -> Result<[u8; 32], PcpError> {
    // Commitment is over the raw bytes, taken before parsing.
    let credential_claim: [u8; 32] = Sha256::digest(hashes_json).into();

    let parsed: HashesJson =
        serde_json::from_slice(hashes_json).map_err(|_| PcpError::InvalidHashesJson)?;

    let committed: [u8; 32] = hex::decode(&parsed.thumbnail_png)
        .map_err(|_| PcpError::InvalidHashesJson)?
        .try_into()
        .map_err(|_| PcpError::InvalidHashesJson)?;

    let observed: [u8; 32] = Sha256::digest(credential_image).into();
    if observed != committed {
        return Err(PcpError::ThumbnailHashMismatch);
    }

    Ok(credential_claim)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::{PcpError, verify_pcp};

    fn hashes_json_for(image: &[u8]) -> Vec<u8> {
        let hash = hex::encode(Sha256::digest(image));
        format!(r#"{{"thumbnail.png":"{hash}","version":"1"}}"#).into_bytes()
    }

    #[test]
    fn binding_succeeds_and_returns_claim() {
        let image = b"credential-thumbnail";
        let hashes_json = hashes_json_for(image);

        let claim = verify_pcp(image, &hashes_json).expect("binding should succeed");

        assert_eq!(claim, Sha256::digest(&hashes_json).as_slice());
    }

    #[test]
    fn credential_claim_is_hash_of_raw_hashes_json() {
        let image = b"another-image";
        let hashes_json = hashes_json_for(image);

        let claim = verify_pcp(image, &hashes_json).expect("binding should succeed");

        // Independent recompute over the raw bytes guards against hashing a
        // parsed/re-serialized form.
        let expected: [u8; 32] = Sha256::digest(&hashes_json).into();
        assert_eq!(claim, expected);
    }

    #[test]
    fn rejects_thumbnail_mismatch() {
        let hashes_json = hashes_json_for(b"the-enrolled-image");

        let result = verify_pcp(b"a-different-image", &hashes_json);

        assert_eq!(result, Err(PcpError::ThumbnailHashMismatch));
    }

    #[test]
    fn rejects_malformed_hashes_json() {
        let result = verify_pcp(b"image", b"not valid json");

        assert_eq!(result, Err(PcpError::InvalidHashesJson));
    }

    #[test]
    fn rejects_missing_thumbnail_entry() {
        // Absent `thumbnail.png` is now a deserialization failure (required field).
        let result = verify_pcp(b"image", br#"{"version":"1"}"#);

        assert_eq!(result, Err(PcpError::InvalidHashesJson));
    }

    #[test]
    fn rejects_bad_thumbnail_hex() {
        let result = verify_pcp(b"image", br#"{"thumbnail.png":"zz"}"#);

        assert_eq!(result, Err(PcpError::InvalidHashesJson));
    }

    #[test]
    fn rejects_wrong_length_thumbnail_hash() {
        // Valid hex, but only 2 bytes instead of 32.
        let result = verify_pcp(b"image", br#"{"thumbnail.png":"abcd"}"#);

        assert_eq!(result, Err(PcpError::InvalidHashesJson));
    }
}

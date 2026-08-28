//! The registry's key: a `BabyJubJub` `EdDSA` public key in canonical text form.

use std::fmt;
use std::str::FromStr;

/// A compressed `BabyJubJub` `EdDSA` public key is always 32 bytes.
pub const SIGNING_PUBLIC_KEY_LEN: usize = 32;

/// A `Signing Key`, as the registry stores it and as `GET /v1/signing-keys/{public_key}` asks
/// for it.
///
/// Canonical text is `0x` followed by 64 lowercase hex digits. Parsing also takes uppercase and a
/// missing prefix: a `404` is a hard verification failure, so a caller's formatting must not be
/// able to produce one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SigningPublicKey([u8; SIGNING_PUBLIC_KEY_LEN]);

/// Why a value is not a signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not a signing key: {0}")]
pub struct InvalidSigningPublicKey(&'static str);

impl SigningPublicKey {
    /// Wraps the compressed bytes of a key.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SIGNING_PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The compressed bytes, as the attestation document's `public_key` field carries them.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SIGNING_PUBLIC_KEY_LEN] {
        &self.0
    }
}

impl TryFrom<&[u8]> for SigningPublicKey {
    type Error = InvalidSigningPublicKey;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <[u8; SIGNING_PUBLIC_KEY_LEN]>::try_from(bytes)
            .map(Self)
            .map_err(|_| InvalidSigningPublicKey("a signing key is 32 bytes"))
    }
}

impl FromStr for SigningPublicKey {
    type Err = InvalidSigningPublicKey;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let digits = text
            .strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .unwrap_or(text);

        if digits.len() != SIGNING_PUBLIC_KEY_LEN * 2 {
            return Err(InvalidSigningPublicKey("expected 64 hex digits"));
        }

        let mut bytes = [0u8; SIGNING_PUBLIC_KEY_LEN];
        hex::decode_to_slice(digits, &mut bytes)
            .map_err(|_| InvalidSigningPublicKey("expected hexadecimal"))?;

        Ok(Self(bytes))
    }
}

impl fmt::Display for SigningPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "0x{}", hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::{SIGNING_PUBLIC_KEY_LEN, SigningPublicKey};

    const KEY: [u8; SIGNING_PUBLIC_KEY_LEN] = [0xab; SIGNING_PUBLIC_KEY_LEN];

    #[test]
    fn canonical_text_round_trips() {
        let key = SigningPublicKey::from_bytes(KEY);
        let text = key.to_string();

        assert!(text.starts_with("0x"));
        assert_eq!(text.len(), 2 + SIGNING_PUBLIC_KEY_LEN * 2);
        assert_eq!(text.parse::<SigningPublicKey>().expect("should parse"), key);
    }

    /// A `404` is terminal for the caller, so the spellings that mean the same key must all
    /// reach the same row rather than one of them missing.
    #[test]
    fn accepts_the_spellings_a_caller_might_send() {
        let canonical = SigningPublicKey::from_bytes(KEY);
        let digits = hex::encode(KEY);

        for text in [
            format!("0x{digits}"),
            digits.clone(),
            format!("0X{}", digits.to_uppercase()),
            digits.to_uppercase(),
        ] {
            assert_eq!(
                text.parse::<SigningPublicKey>().expect("should parse"),
                canonical,
                "{text} should be the same key"
            );
        }
    }

    #[test]
    fn rejects_anything_that_is_not_a_key() {
        for text in [
            "",
            "0x",
            "not-hex",
            &hex::encode([0u8; SIGNING_PUBLIC_KEY_LEN - 1]),
            &hex::encode([0u8; SIGNING_PUBLIC_KEY_LEN + 1]),
            &format!("0x{}", "z".repeat(SIGNING_PUBLIC_KEY_LEN * 2)),
        ] {
            assert!(
                text.parse::<SigningPublicKey>().is_err(),
                "{text} should not parse"
            );
        }
    }

    #[test]
    fn bytes_convert_only_at_the_right_length() {
        assert!(SigningPublicKey::try_from(KEY.as_slice()).is_ok());
        assert!(SigningPublicKey::try_from([0u8; 31].as_slice()).is_err());
        assert!(SigningPublicKey::try_from([0u8; 33].as_slice()).is_err());
    }
}

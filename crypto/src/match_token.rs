//! Match-result tokens: CWTs (RFC 8392) carrying private claims.
//! Note: This is a WIP module and will probably move to the `world-id-protocol` repo.
//!
//! The enclave signs the match claims; the client verifies them before using them in a `DeepFace`
//! proof.
//! The cryptography follows the `world-id-protocol` Trust Anchor Key Token — a Poseidon2 BN254
//! digest, `BabyJubJub` `EdDSA` signature, and untagged `COSE_Sign1` envelope — because a ZK
//! circuit has to verify it, which rules out the standard COSE algorithms.
//!
//! Not an EAT (RFC 9711): this asserts the result of a computation, not the enclave's own state.
//! The enclave attests itself with a separate Nitro document.
//!
//! # Provisional format
//!
//! The five claim keys, [`DOMAIN_SEPARATOR`], and [`MATCH_COEFFICIENT_SCALE`] require protocol
//! agreement. Changing any is wire-breaking.
//!
//! The coefficient is scaled to an integer because a BN254 field element is one. The scale must
//! match whatever consumes the token. Only non-negative values are representable, which costs
//! nothing here: a token is signed only for a match at or above the threshold.
//!
//! # What the signature covers
//!
//! The four digest fields, and nothing else. [`MatchTokenSigner::sign`] sets the `COSE_Sign1`
//! signature directly instead of signing the `Sig_structure` (RFC 9052 §4.4), because a circuit
//! cannot cheaply hash CBOR — so `coset` supplies the envelope, not the signing, as in the
//! reference `TrustAnchorKeyToken`. Payload bytes, `alg`, `kid`, and [`TOKEN_VERSION`] all sit
//! outside the signature: [`verify`] checks `alg` itself, and takes the public key from its caller
//! rather than from `kid`.
//!
//! # Versioning
//!
//! [`DOMAIN_SEPARATOR`] enforces the version: hashed into the digest, so a token from one version
//! cannot verify under another. [`TOKEN_VERSION`] is advisory, and turns honest version skew into a
//! legible error instead of a bare signature failure. It has to ship in v1 to do that — a verifier
//! only reports a mismatch it knows to look for — so [`CLAIM_VERSION`] and its type are frozen
//! across versions. Bump both constants together.
//!
//! # Claim lowering
//!
//! As in `world-id-protocol`, values wider than 128 bits split into big-endian limbs. Three hashes
//! give six limbs; the coefficient and domain separator complete the Poseidon2 `t8` input.

use ark_babyjubjub::Fq;
use ark_ff::PrimeField;
use coset::{
    CborSerializable, CoseSign1, CoseSign1Builder, Header, RegisteredLabelWithPrivate,
    cbor::value::Value,
};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey};

/// COSE algorithm identifier for `BabyJubJub-EdDSA-Poseidon2`, as defined in WIP-106.
pub const COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2: i64 = -65537;

/// Version of this token's encoding: the claim keys and [`MATCH_COEFFICIENT_SCALE`].
///
/// Advisory, not enforced — see the module docs. Bump with [`DOMAIN_SEPARATOR`].
pub const TOKEN_VERSION: u64 = 1;

/// Domain separator folded into the Poseidon2 state before any claim.
///
/// Carries the version and is what enforces it. Bump with [`TOKEN_VERSION`]. Provisional.
const DOMAIN_SEPARATOR: &[u8] = b"WORLD_ID_DFVT_V1";

// The `-81_00x` block is unallocated: WIP-106's own private claims sit at `-80_000`, `-80_001`, and
// `-70_000`, so these five keep clear of those while staying in the same negative range. Nothing
// reserves the block for us, which is what makes the keys provisional — ratification is pending.

/// Private CWT claim key for [`TOKEN_VERSION`]. Frozen across versions; never renumber.
pub const CLAIM_VERSION: i64 = -81_004;

/// Private CWT claim key for `live_image_hash`. Provisional.
pub const CLAIM_LIVE_IMAGE_HASH: i64 = -81_000;
/// Private CWT claim key for `credential_claim`. Provisional.
pub const CLAIM_CREDENTIAL_CLAIM: i64 = -81_001;
/// Private CWT claim key for `challenger_image_hash`. Provisional.
pub const CLAIM_CHALLENGER_IMAGE_HASH: i64 = -81_002;
/// Private CWT claim key for `match_coefficient`. Provisional.
pub const CLAIM_MATCH_COEFFICIENT: i64 = -81_003;

/// Fixed-point scale applied to `match_coefficient` before it becomes a field element.
///
/// A power of two so unscaling is a shift. `f32` carries ~24 mantissa bits, so the low six are
/// noise. Provisional.
pub const MATCH_COEFFICIENT_SCALE: u32 = 1 << 30;

/// Width of the Poseidon2 permutation the digest uses.
const POSEIDON2_WIDTH: usize = 8;

/// Number of field elements the claims lower to: two limbs per hash plus the coefficient.
const CLAIM_ELEMENTS: usize = 7;

// The domain separator occupies slot 0 and the claims fill the rest exactly. Checked at compile
// time so adding a claim cannot silently overflow the permutation.
const _: () = assert!(CLAIM_ELEMENTS + 1 == POSEIDON2_WIDTH);

/// Length of a compressed `BabyJubJub` public key, which is what the enclave attests.
pub const SIGNING_KEY_LEN: usize = 32;

/// Why a match token could not be signed or verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchTokenError {
    /// The supplied signing public key was not a valid `BabyJubJub` point.
    InvalidSigningKey,
    /// `match_coefficient` was negative, not finite, or too large to scale into the field.
    UnrepresentableCoefficient,
    /// Encoding the claims set as CBOR failed.
    CborEncoding,
    /// Serializing a key or signature failed.
    KeyEncoding,
    /// The token was not a `COSE_Sign1`, or its claims were not the expected shape.
    MalformedToken,
    /// The token's protected header did not name [`COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2`].
    UnexpectedAlgorithm,
    /// The token declared a version other than [`TOKEN_VERSION`].
    UnexpectedVersion,
    /// The signature did not verify under the supplied public key.
    SignatureInvalid,
}

/// The claims a match token commits to.
///
/// `challenger_image_hash` is always present: v1 implements the 3-way flow only.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MatchClaims {
    /// SHA-256 of the live image.
    pub live_image_hash: [u8; 32],
    /// PCP commitment `SHA256(hashes.json)`. A commitment, not proof of enrollment — the circuit
    /// binds it to an issuer-signed credential.
    pub credential_claim: [u8; 32],
    /// SHA-256 of the challenge image.
    pub challenger_image_hash: [u8; 32],
    /// Credential-vs-live similarity.
    pub match_coefficient: f32,
}

impl MatchClaims {
    /// Builds the CWT claims set as a deterministic CBOR map.
    ///
    /// Keys are inserted in RFC 8949 §4.2.1 order — all five are negative integers of equal
    /// encoded width, so ascending by magnitude — letting the circuit read them at fixed offsets.
    fn claims(&self) -> Result<Vec<u8>, MatchTokenError> {
        let claims = Value::Map(vec![
            (
                Value::Integer(CLAIM_LIVE_IMAGE_HASH.into()),
                Value::Bytes(self.live_image_hash.to_vec()),
            ),
            (
                Value::Integer(CLAIM_CREDENTIAL_CLAIM.into()),
                Value::Bytes(self.credential_claim.to_vec()),
            ),
            (
                Value::Integer(CLAIM_CHALLENGER_IMAGE_HASH.into()),
                Value::Bytes(self.challenger_image_hash.to_vec()),
            ),
            (
                Value::Integer(CLAIM_MATCH_COEFFICIENT.into()),
                Value::Integer(self.scaled_coefficient()?.into()),
            ),
            (
                Value::Integer(CLAIM_VERSION.into()),
                Value::Integer(TOKEN_VERSION.into()),
            ),
        ]);

        let mut encoded = Vec::new();
        coset::cbor::into_writer(&claims, &mut encoded)
            .map_err(|_| MatchTokenError::CborEncoding)?;

        Ok(encoded)
    }

    /// Scales `match_coefficient` into a non-negative fixed-point integer.
    ///
    /// # Errors
    ///
    /// Returns [`MatchTokenError::UnrepresentableCoefficient`] if the score is not finite, is
    /// negative, or does not fit the fixed-point integer. Claims that cannot commit to their own
    /// score are not signed at all.
    fn scaled_coefficient(&self) -> Result<u32, MatchTokenError> {
        // NaN and infinity have no field-element representation, and the target is unsigned.
        if !self.match_coefficient.is_finite() || self.match_coefficient < 0.0 {
            return Err(MatchTokenError::UnrepresentableCoefficient);
        }

        // Both operands widen losslessly.
        let scaled =
            (f64::from(self.match_coefficient) * f64::from(MATCH_COEFFICIENT_SCALE)).round();

        // `u32::MAX` converts to `f64` exactly, so this bounds by what the encoding holds.
        if scaled > f64::from(u32::MAX) {
            return Err(MatchTokenError::UnrepresentableCoefficient);
        }

        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "non-negative and bounded by the checks above"
        )]
        Ok(scaled as u32)
    }

    /// Lowers the claims into the Poseidon2 state and returns the digest.
    ///
    /// Slot 0 holds the domain separator; the remaining seven hold the claim elements. The digest
    /// is element 1 of the permuted state, matching the Trust Anchor Key Token.
    ///
    /// # Errors
    ///
    /// Returns [`MatchTokenError`] if `match_coefficient` cannot be represented.
    pub fn message_hash(&self) -> Result<Fq, MatchTokenError> {
        let coefficient = self.scaled_coefficient()?;

        let mut state = [Fq::from(0u64); POSEIDON2_WIDTH];
        // 16 bytes, so `mod_order` cannot reduce it; the call is the lowering WIP-106 specifies.
        state[0] = Fq::from_be_bytes_mod_order(DOMAIN_SEPARATOR);

        let mut slot = 1;
        for hash in [
            &self.live_image_hash,
            &self.credential_claim,
            &self.challenger_image_hash,
        ] {
            for limb in hash_limbs(hash) {
                state[slot] = limb;
                slot += 1;
            }
        }
        state[slot] = Fq::from(coefficient);

        poseidon2::bn254::t8::permutation_in_place(&mut state);

        Ok(state[1])
    }
}

/// The enclave's side of the match-token flow: a boot-scoped `BabyJubJub` `EdDSA` keypair.
///
/// The compressed public key is derived once at generation, so reading it — and therefore
/// attesting it — cannot fail.
pub struct MatchTokenSigner {
    private_key: EdDSAPrivateKey,
    public_key: [u8; SIGNING_KEY_LEN],
}

impl MatchTokenSigner {
    /// Generates a fresh keypair from `rng`.
    ///
    /// Takes the rand 0.8 traits `eddsa-babyjubjub` speaks, unlike the sealed channel's
    /// `rand_core` 0.10 parameter. In an enclave both draw from the Nitro hardware RNG.
    ///
    /// # Panics
    ///
    /// Panics if the generated public key does not serialize, which the curve makes impossible.
    /// Failing at boot beats failing per request.
    #[must_use]
    pub fn generate<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> Self {
        let private_key = EdDSAPrivateKey::random(rng);
        let public_key = private_key
            .public()
            .to_compressed_bytes()
            .expect("a generated BabyJubJub public key serializes");

        Self {
            private_key,
            public_key,
        }
    }

    /// Returns the compressed public key that verifies this boot's match tokens, as carried in the
    /// `public_key` field of the enclave's signing-key attestation.
    #[must_use]
    pub const fn public_key(&self) -> [u8; SIGNING_KEY_LEN] {
        self.public_key
    }

    /// Signs `claims` and serializes them as an untagged `COSE_Sign1`.
    ///
    /// The protected header carries [`COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2`] and a `kid` holding the
    /// compressed public key; the signature covers [`MatchClaims::message_hash`].
    ///
    /// # Errors
    ///
    /// Returns [`MatchTokenError`] if the coefficient cannot be represented, or if the claims or
    /// signature cannot be serialized.
    pub fn sign(&self, claims: &MatchClaims) -> Result<Vec<u8>, MatchTokenError> {
        let signature = self
            .private_key
            .sign(claims.message_hash()?)
            .to_compressed_bytes()
            .map_err(|_| MatchTokenError::KeyEncoding)?;

        let protected = Header {
            alg: Some(RegisteredLabelWithPrivate::PrivateUse(
                COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2,
            )),
            key_id: self.public_key.to_vec(),
            ..Header::default()
        };

        CoseSign1Builder::new()
            .protected(protected)
            .payload(claims.claims()?)
            .signature(signature.to_vec())
            .build()
            .to_vec()
            .map_err(|_| MatchTokenError::CborEncoding)
    }
}

/// Splits a 32-byte hash into two 128-bit big-endian limbs.
///
/// A 32-byte value can exceed the `BabyJubJub` base field modulus (~254 bits), so lowering it as
/// one element risks reduction. Matches how `world-id-protocol` lowers `cnf` coordinates.
fn hash_limbs(hash: &[u8; 32]) -> [Fq; 2] {
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&hash[..16]);
    lo.copy_from_slice(&hash[16..]);

    [
        Fq::from(u128::from_be_bytes(hi)),
        Fq::from(u128::from_be_bytes(lo)),
    ]
}

/// Verifies a serialized match token and returns the claims it commits to.
///
/// `signing_public_key` is the compressed key a client reads from the *verified* signing-key
/// attestation document, so it arrives as raw bytes rather than a curve type.
///
/// Nothing is returned until the signature verifies, and the digest is recomputed from the parsed
/// claims rather than trusted, so a token whose payload disagrees with its signature fails.
///
/// # Errors
///
/// Returns [`MatchTokenError`] if the key is not a valid point, the token is not a well-formed
/// `COSE_Sign1`, names another algorithm, carries claims of an unexpected shape, or fails
/// signature verification.
pub fn verify(
    token: &[u8],
    signing_public_key: &[u8; SIGNING_KEY_LEN],
) -> Result<MatchClaims, MatchTokenError> {
    let public_key = EdDSAPublicKey::from_compressed_bytes(*signing_public_key)
        .map_err(|_| MatchTokenError::InvalidSigningKey)?;

    let sign1 = CoseSign1::from_slice(token).map_err(|_| MatchTokenError::MalformedToken)?;

    match sign1.protected.header.alg {
        Some(RegisteredLabelWithPrivate::PrivateUse(COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2)) => {}
        _ => return Err(MatchTokenError::UnexpectedAlgorithm),
    }

    let payload = sign1
        .payload
        .as_deref()
        .ok_or(MatchTokenError::MalformedToken)?;
    let claims = decode_claims(payload)?;

    let signature = <[u8; 64]>::try_from(sign1.signature.as_slice())
        .map_err(|_| MatchTokenError::MalformedToken)
        .and_then(|bytes| {
            eddsa_babyjubjub::EdDSASignature::from_compressed_bytes(bytes)
                .map_err(|_| MatchTokenError::MalformedToken)
        })?;

    if public_key.verify(claims.message_hash()?, &signature) {
        Ok(claims)
    } else {
        Err(MatchTokenError::SignatureInvalid)
    }
}

/// Rebuilds [`MatchClaims`] from an encoded claims set.
fn decode_claims(payload: &[u8]) -> Result<MatchClaims, MatchTokenError> {
    let claims: Value =
        coset::cbor::from_reader(payload).map_err(|_| MatchTokenError::MalformedToken)?;
    let entries = claims.as_map().ok_or(MatchTokenError::MalformedToken)?;

    let lookup = |key: i64| {
        entries
            .iter()
            .find(|(k, _)| k.as_integer() == Some(key.into()))
            .map(|(_, v)| v)
            .ok_or(MatchTokenError::MalformedToken)
    };

    let hash = |key: i64| -> Result<[u8; 32], MatchTokenError> {
        lookup(key)?
            .as_bytes()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            .ok_or(MatchTokenError::MalformedToken)
    };

    // Checked before any value is interpreted: another version means different scaling rules.
    let version = lookup(CLAIM_VERSION)?
        .as_integer()
        .and_then(|value| u64::try_from(i128::from(value)).ok())
        .ok_or(MatchTokenError::MalformedToken)?;
    if version != TOKEN_VERSION {
        return Err(MatchTokenError::UnexpectedVersion);
    }

    // Bounded to `u32`, which is all `scaled_coefficient` produces, so the widening is lossless.
    let scaled = lookup(CLAIM_MATCH_COEFFICIENT)?
        .as_integer()
        .and_then(|value| u32::try_from(i128::from(value)).ok())
        .ok_or(MatchTokenError::MalformedToken)?;

    let unscaled = f64::from(scaled) / f64::from(MATCH_COEFFICIENT_SCALE);

    #[expect(
        clippy::cast_possible_truncation,
        reason = "narrowing back to the f32 the claims were built from is the intent"
    )]
    let match_coefficient = unscaled as f32;

    Ok(MatchClaims {
        live_image_hash: hash(CLAIM_LIVE_IMAGE_HASH)?,
        credential_claim: hash(CLAIM_CREDENTIAL_CLAIM)?,
        challenger_image_hash: hash(CLAIM_CHALLENGER_IMAGE_HASH)?,
        match_coefficient,
    })
}

#[cfg(test)]
mod tests {
    use ark_babyjubjub::Fq;
    use coset::{CborSerializable as _, CoseSign1, CoseSign1Builder, cbor::value::Value};

    use super::{
        CLAIM_VERSION, COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2, MATCH_COEFFICIENT_SCALE, MatchClaims,
        MatchTokenError, MatchTokenSigner, TOKEN_VERSION, hash_limbs, verify,
    };

    fn signer() -> MatchTokenSigner {
        MatchTokenSigner::generate(&mut rand::rngs::OsRng)
    }

    fn claims() -> MatchClaims {
        MatchClaims {
            live_image_hash: [1u8; 32],
            credential_claim: [2u8; 32],
            challenger_image_hash: [3u8; 32],
            match_coefficient: 0.9375,
        }
    }

    #[test]
    fn round_trips_through_sign_and_verify() {
        let signing_key = signer();
        let original = claims();

        let token = signing_key.sign(&original).expect("signing should succeed");
        let verified = verify(&token, &signing_key.public_key())
            .expect("the token should verify under its key");

        assert_eq!(verified.live_image_hash, original.live_image_hash);
        assert_eq!(verified.credential_claim, original.credential_claim);
        assert_eq!(
            verified.challenger_image_hash,
            original.challenger_image_hash
        );
        // 0.9375 is exactly representable at this scale, so the round trip is lossless.
        assert_eq!(
            verified.match_coefficient.to_bits(),
            original.match_coefficient.to_bits()
        );
    }

    #[test]
    fn rejects_a_token_signed_by_another_key() {
        let token = signer().sign(&claims()).expect("signing should succeed");

        assert_eq!(
            verify(&token, &signer().public_key()).err(),
            Some(MatchTokenError::SignatureInvalid)
        );
    }

    #[test]
    fn rejects_a_mutated_claim() {
        let signing_key = signer();
        let mut token = signing_key.sign(&claims()).expect("signing should succeed");

        // The digest is recomputed from the parsed claims, so a flipped byte breaks the match.
        let middle = token.len() / 2;
        token[middle] ^= 0x01;

        assert!(matches!(
            verify(&token, &signing_key.public_key()),
            Err(MatchTokenError::SignatureInvalid | MatchTokenError::MalformedToken)
        ));
    }

    #[test]
    fn every_claim_is_committed_by_the_digest() {
        let base = claims().message_hash().expect("hashing should succeed");

        for mutated in [
            MatchClaims {
                live_image_hash: [9u8; 32],
                ..claims()
            },
            MatchClaims {
                credential_claim: [9u8; 32],
                ..claims()
            },
            MatchClaims {
                challenger_image_hash: [9u8; 32],
                ..claims()
            },
            MatchClaims {
                match_coefficient: 0.875,
                ..claims()
            },
        ] {
            assert_ne!(
                base,
                mutated.message_hash().expect("hashing should succeed"),
                "digest must change when a claim changes"
            );
        }
    }

    #[test]
    fn digest_is_stable_for_one_claim_set() {
        let first = claims().message_hash().expect("hashing should succeed");
        let second = claims().message_hash().expect("hashing should succeed");

        assert_eq!(first, second);
    }

    #[test]
    fn hash_limbs_split_big_endian() {
        let mut hash = [0u8; 32];
        hash[15] = 1;
        hash[31] = 2;

        assert_eq!(hash_limbs(&hash), [Fq::from(1u64), Fq::from(2u64)]);
    }

    #[test]
    fn hash_limbs_distinguish_halves() {
        let mut swapped = [0u8; 32];
        swapped[0] = 1;
        let mut other = [0u8; 32];
        other[16] = 1;

        assert_ne!(hash_limbs(&swapped), hash_limbs(&other));
    }

    #[test]
    fn rejects_a_token_declaring_another_version() {
        // The version is not in the digest, so a bumped version keeps a valid signature. Only
        // the explicit check catches this.
        let signing_key = signer();
        let token = signing_key.sign(&claims()).expect("signing should succeed");
        let sign1 = CoseSign1::from_slice(&token).expect("token should parse");

        let payload = sign1.payload.as_deref().expect("payload should be present");
        let mut entries = coset::cbor::from_reader::<Value, _>(payload)
            .expect("payload should decode")
            .into_map()
            .expect("claims are a map");
        for (key, value) in &mut entries {
            if key.as_integer() == Some(CLAIM_VERSION.into()) {
                *value = Value::Integer((TOKEN_VERSION + 1).into());
            }
        }
        let mut repacked = Vec::new();
        coset::cbor::into_writer(&Value::Map(entries), &mut repacked).expect("should re-encode");

        let forged = CoseSign1Builder::new()
            .protected(sign1.protected.header.clone())
            .payload(repacked)
            .signature(sign1.signature.clone())
            .build()
            .to_vec()
            .expect("should serialize");

        // Not SignatureInvalid: the signature genuinely still verifies.
        assert_eq!(
            verify(&forged, &signing_key.public_key()).err(),
            Some(MatchTokenError::UnexpectedVersion)
        );
    }

    #[test]
    fn rejects_a_coefficient_the_encoding_cannot_hold() {
        // Far beyond any similarity; bounded by the integer, not by policy.
        let claims = MatchClaims {
            match_coefficient: 8.0e9,
            ..claims()
        };

        assert_eq!(
            claims.message_hash().err(),
            Some(MatchTokenError::UnrepresentableCoefficient)
        );
    }

    #[test]
    fn rejects_a_negative_coefficient() {
        // Unreachable in the enclave, but fail closed anyway.
        let claims = MatchClaims {
            match_coefficient: -0.5,
            ..claims()
        };

        assert_eq!(
            claims.message_hash().err(),
            Some(MatchTokenError::UnrepresentableCoefficient)
        );
    }

    #[test]
    fn rejects_a_non_finite_coefficient() {
        for coefficient in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let claims = MatchClaims {
                match_coefficient: coefficient,
                ..claims()
            };

            assert_eq!(
                signer().sign(&claims).err(),
                Some(MatchTokenError::UnrepresentableCoefficient),
                "{coefficient} must not be signed"
            );
        }
    }

    #[test]
    fn coefficient_scaling_is_order_preserving() {
        // The property the circuit's threshold comparison depends on.
        let scaled = |coefficient: f32| {
            MatchClaims {
                match_coefficient: coefficient,
                ..claims()
            }
            .scaled_coefficient()
            .expect("in-range coefficient")
        };

        let mut previous = scaled(0.0);
        for step in 1..=20u8 {
            let current = scaled(f32::from(step) / 20.0);
            assert!(current > previous, "scaling must be strictly increasing");
            previous = current;
        }
    }

    #[test]
    fn scale_is_a_power_of_two() {
        assert!(MATCH_COEFFICIENT_SCALE.is_power_of_two());
    }

    #[test]
    fn protected_header_names_the_wip_106_algorithm() {
        let signing_key = signer();
        let token = signing_key.sign(&claims()).expect("signing should succeed");

        let sign1 = coset::CoseSign1::from_slice(&token).expect("token should be a COSE_Sign1");
        assert_eq!(
            sign1.protected.header.alg,
            Some(coset::RegisteredLabelWithPrivate::PrivateUse(
                COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2
            ))
        );
        // `kid` lets a verifier find the key; it is not trusted in place of one.
        assert_eq!(
            sign1.protected.header.key_id,
            signing_key.public_key().to_vec()
        );
    }

    #[test]
    fn claims_are_in_deterministic_cbor_order() {
        // The circuit reads claims at constant offsets, so the encoded key order is contractual.
        let payload = claims().claims().expect("claims should encode");
        let claims: coset::cbor::value::Value =
            coset::cbor::from_reader(payload.as_slice()).expect("claims should decode");
        let keys: Vec<i128> = claims
            .as_map()
            .expect("claims are a map")
            .iter()
            .map(|(key, _)| i128::from(key.as_integer().expect("integer key")))
            .collect();

        let mut expected = keys.clone();
        // RFC 8949 §4.2.1: equal-width negatives, so ascending by magnitude.
        expected.sort_by_key(|key| (i32::from(*key < 0), key.abs()));

        assert_eq!(keys, expected);
        // The version sorts last despite being read first, so lookup cannot rely on position.
        assert_eq!(keys.last(), Some(&i128::from(CLAIM_VERSION)));
        assert_eq!(keys.len(), 5);
    }
}

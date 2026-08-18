//! Tests for the Nitro attestation verifier.
//!
//! The negative cases are ported from `worldcoin/bedrock`
//! (`bedrock/src/nitro_enclave/tests.rs`), MIT © Tools for Humanity, along with the real
//! attestation document in `testdata/`, which was produced by a live enclave.
//!
//! That document's certificate chain expired in September 2025, so every test pins `now` to
//! the document's own timestamp. Unlike bedrock, which needed a `cfg(test)` flag to bypass
//! the certificate time check, this exercises exactly the production code path — the clock is
//! just an argument.

// `Duration::from_days` / `from_hours`, which clippy suggests here, are unstable on the
// toolchain this workspace pins (1.97).
#![allow(clippy::duration_suboptimal_units)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hex_literal::hex;

use super::{
    AWS_NITRO_ROOT_CERT, EnclaveAttestationError, EnclaveAttestationVerifier, PcrMeasurement,
};

/// A real attestation document captured from a live Nitro enclave.
const REAL_ATTESTATION_DOC_BASE64: &str = include_str!("testdata/real_attestation_doc.b64");

/// Ten years, so the ported fixture is never rejected for staleness.
const GENEROUS_MAX_AGE_MILLIS: u64 = 10 * 365 * 24 * 60 * 60 * 1000;

fn real_document() -> Vec<u8> {
    STANDARD
        .decode(REAL_ATTESTATION_DOC_BASE64.trim())
        .expect("fixture should be valid base64")
}

/// The PCRs the fixture's enclave actually reported.
fn fixture_pcr_config() -> Vec<PcrMeasurement> {
    vec![
        PcrMeasurement::new(
            0,
            hex!(
                "108b32466f5dc0a9971e0bc8e3e4074e7821bb2dcad3841bdec9a08b30f173386f0394a01486df181f316b39443dab34"
            ),
        ),
        PcrMeasurement::new(
            1,
            hex!(
                "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493"
            ),
        ),
        PcrMeasurement::new(
            2,
            hex!(
                "08c6b2cba2d0c0ab63f3533cb44e092fb211775323cd62cd571f871e127ae1844f0e948a54ba58ecd29fbe03a64d5edc"
            ),
        ),
        PcrMeasurement::new(
            8,
            hex!(
                "b38251662033340b540c2d7e5f49e7ec6d10afcb5f17c72132e20a7f0a54576dc4d2c6ce062ed2ed2b6ae01815d69c8d"
            ),
        ),
    ]
}

fn verifier() -> EnclaveAttestationVerifier {
    EnclaveAttestationVerifier::new(vec![fixture_pcr_config()], GENEROUS_MAX_AGE_MILLIS)
}

/// The instant the fixture was produced, read from the document itself.
///
/// Using the document's own timestamp puts `now` inside the certificate validity window
/// without hardcoding a date that would drift from the fixture.
fn fixture_instant() -> SystemTime {
    let bytes = real_document();
    let cose = EnclaveAttestationVerifier::parse_cose_sign1(&bytes).expect("fixture should parse");
    let doc = EnclaveAttestationVerifier::parse_cbor_payload(&cose).expect("fixture should decode");

    UNIX_EPOCH + Duration::from_millis(doc.timestamp)
}

#[test]
fn verifies_a_real_attestation_document() {
    let verified = verifier()
        .verify(&real_document(), fixture_instant())
        .expect("the fixture should verify against the pinned AWS root");

    assert!(
        verified.module_id.contains("-enc"),
        "module id should name an enclave, got {}",
        verified.module_id
    );
    assert_eq!(
        verified.enclave_public_key.len(),
        32,
        "the fixture attests a 32-byte X25519 key"
    );
    assert_eq!(
        verified.pcrs.get(&0).map(Vec::as_slice),
        Some(fixture_pcr_config()[0].value.as_slice())
    );
}

#[test]
fn verifies_the_same_document_through_the_base64_entry_point() {
    let verified = verifier()
        .verify_base64(REAL_ATTESTATION_DOC_BASE64.trim(), fixture_instant())
        .expect("the fixture should verify");

    assert_eq!(verified.timestamp_millis, {
        let bytes = real_document();
        let cose = EnclaveAttestationVerifier::parse_cose_sign1(&bytes).unwrap();
        EnclaveAttestationVerifier::parse_cbor_payload(&cose)
            .unwrap()
            .timestamp
    });
}

#[test]
fn rejects_a_tampered_payload() {
    let mut bytes = real_document();
    // Flip a byte deep inside the COSE payload, leaving the framing intact.
    let midpoint = bytes.len() / 2;
    bytes[midpoint] ^= 0xff;

    let error = verifier()
        .verify(&bytes, fixture_instant())
        .expect_err("a tampered document must not verify");

    assert!(
        matches!(
            error,
            EnclaveAttestationError::AttestationSignatureInvalid(_)
                | EnclaveAttestationError::AttestationDocumentParseError(_)
                | EnclaveAttestationError::AttestationChainInvalid(_)
        ),
        "unexpected error: {error}"
    );
}

/// Corrupts only the COSE signature, leaving the document and its chain intact.
///
/// This is the test that proves signature verification actually runs: everything else about
/// the document still parses and still chains to the pinned AWS root.
#[test]
fn rejects_a_corrupted_cose_signature() {
    let bytes = real_document();
    let ciborium::Value::Array(mut fields) =
        ciborium::from_reader::<ciborium::Value, _>(bytes.as_slice()).expect("fixture is CBOR")
    else {
        panic!("a COSE_Sign1 document is a CBOR array");
    };

    let ciborium::Value::Bytes(signature) = &mut fields[3] else {
        panic!("the fourth COSE_Sign1 field is the signature");
    };
    signature[0] ^= 0xff;

    let mut tampered = Vec::new();
    ciborium::into_writer(&ciborium::Value::Array(fields), &mut tampered)
        .expect("re-encoding should succeed");

    let error = verifier()
        .verify(&tampered, fixture_instant())
        .expect_err("a document with a corrupted signature must not verify");

    assert!(
        matches!(
            error,
            EnclaveAttestationError::AttestationSignatureInvalid(_)
        ),
        "expected a signature failure, got: {error}"
    );
}

#[test]
fn rejects_a_truncated_signature() {
    let bytes = real_document();
    let mut truncated = bytes.clone();
    truncated.truncate(bytes.len() - 1);

    let error = verifier()
        .verify(&truncated, fixture_instant())
        .expect_err("a truncated document must not verify");

    assert!(
        matches!(
            error,
            EnclaveAttestationError::AttestationDocumentParseError(_)
                | EnclaveAttestationError::AttestationSignatureInvalid(_)
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn rejects_a_document_under_a_different_root() {
    // The fixture's own leaf certificate is a valid DER certificate but not the AWS root.
    let not_the_root = {
        let bytes = real_document();
        let cose = EnclaveAttestationVerifier::parse_cose_sign1(&bytes).unwrap();
        let doc = EnclaveAttestationVerifier::parse_cbor_payload(&cose).unwrap();
        doc.certificate.to_vec()
    };

    let error = verifier()
        .with_root_certificate(not_the_root)
        .verify(&real_document(), fixture_instant())
        .expect_err("a chain that does not reach the pinned root must not verify");

    assert!(
        matches!(error, EnclaveAttestationError::AttestationChainInvalid(_)),
        "unexpected error: {error}"
    );
}

#[test]
fn rejects_an_expired_certificate_chain() {
    // One year past the fixture's certificate window.
    let much_later = fixture_instant() + Duration::from_secs(365 * 24 * 60 * 60);

    let error = verifier()
        .verify(&real_document(), much_later)
        .expect_err("an expired chain must not verify");

    assert!(
        matches!(error, EnclaveAttestationError::AttestationChainInvalid(_)),
        "unexpected error: {error}"
    );
}

#[test]
fn rejects_mismatched_pcrs() {
    let wrong = vec![vec![PcrMeasurement::new(0, [0xabu8; 48])]];

    let error = EnclaveAttestationVerifier::new(wrong, GENEROUS_MAX_AGE_MILLIS)
        .verify(&real_document(), fixture_instant())
        .expect_err("an enclave running unexpected code must not verify");

    assert!(
        matches!(error, EnclaveAttestationError::CodeUntrusted { .. }),
        "unexpected error: {error}"
    );
}

#[test]
fn rejects_a_pinned_pcr_index_absent_from_the_document() {
    // Index 20 is a valid PCR index that this document does not carry.
    let mut config = fixture_pcr_config();
    config.push(PcrMeasurement::new(20, [0x11u8; 48]));

    let error = EnclaveAttestationVerifier::new(vec![config], GENEROUS_MAX_AGE_MILLIS)
        .verify(&real_document(), fixture_instant())
        .expect_err("a pinned PCR that is absent must not be silently skipped");

    assert!(
        matches!(error, EnclaveAttestationError::CodeUntrusted { .. }),
        "unexpected error: {error}"
    );
}

#[test]
fn rejects_when_no_pcr_configuration_is_allowed() {
    let error = EnclaveAttestationVerifier::new(Vec::new(), GENEROUS_MAX_AGE_MILLIS)
        .verify(&real_document(), fixture_instant())
        .expect_err("an empty policy must fail closed, not accept everything");

    assert!(
        matches!(error, EnclaveAttestationError::CodeUntrusted { .. }),
        "unexpected error: {error}"
    );
}

#[test]
fn accepts_a_document_matching_any_one_of_several_configurations() {
    // A rollout trusts the outgoing and incoming enclave versions at once.
    let configs = vec![
        vec![PcrMeasurement::new(0, [0xabu8; 48])],
        fixture_pcr_config(),
    ];

    EnclaveAttestationVerifier::new(configs, GENEROUS_MAX_AGE_MILLIS)
        .verify(&real_document(), fixture_instant())
        .expect("matching the second configuration should be enough");
}

#[test]
fn rejects_a_stale_document() {
    let max_age_millis = 60_000;
    let later = fixture_instant() + Duration::from_millis(max_age_millis * 2);

    let error = EnclaveAttestationVerifier::new(vec![fixture_pcr_config()], max_age_millis)
        .verify(&real_document(), later)
        .expect_err("a document older than the policy allows must not verify");

    // The certificate window is only hours wide, so an expired chain is also acceptable here.
    assert!(
        matches!(
            error,
            EnclaveAttestationError::AttestationStale { .. }
                | EnclaveAttestationError::AttestationChainInvalid(_)
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn rejects_a_document_timestamped_in_the_future() {
    let earlier = fixture_instant() - Duration::from_secs(60 * 60);

    let error = verifier()
        .verify(&real_document(), earlier)
        .expect_err("a document from the future must not verify");

    assert!(
        matches!(
            error,
            EnclaveAttestationError::AttestationInvalidTimestamp(_)
                | EnclaveAttestationError::AttestationChainInvalid(_)
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn rejects_empty_and_non_cbor_input() {
    let now = fixture_instant();

    for (label, bytes) in [
        ("empty", Vec::new()),
        ("not CBOR at all", b"hello, world".to_vec()),
        ("a CBOR map rather than an array", vec![0xa1, 0x01, 0x02]),
    ] {
        let error = verifier()
            .verify(&bytes, now)
            .expect_err(&format!("{label} input should be rejected"));

        assert!(
            matches!(
                error,
                EnclaveAttestationError::AttestationDocumentParseError(_)
            ),
            "{label} should fail parsing, got: {error}"
        );
    }
}

/// The pontifex mock fixture carries a two-byte fake certificate and is signed by nothing.
///
/// `pontifex::SecureModule::parse_raw_attestation_doc` accepts it, because it extracts the
/// payload without checking the signature. It must not survive real verification.
#[test]
fn rejects_a_document_with_a_bogus_certificate() {
    // A COSE_Sign1 array whose payload is not a valid attestation document.
    let bogus = vec![0x84, 0x40, 0xa0, 0x42, 0x03, 0x04, 0x41, 0x00];

    let error = verifier()
        .verify(&bogus, fixture_instant())
        .expect_err("a document with a fake certificate must not verify");

    assert!(
        matches!(
            error,
            EnclaveAttestationError::AttestationDocumentParseError(_)
                | EnclaveAttestationError::AttestationChainInvalid(_)
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn pins_the_aws_nitro_root_certificate() {
    use sha2::{Digest as _, Sha256};

    // The fingerprint AWS publishes at
    // https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
    let expected = hex!("641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b");

    assert_eq!(
        Sha256::digest(AWS_NITRO_ROOT_CERT).as_slice(),
        expected.as_slice(),
        "the vendored trust anchor must be the certificate AWS publishes"
    );
}

//! Tests for the Nitro attestation verifier.
//!
//! Cases and the real attestation document are ported from `worldcoin/bedrock`
//! (`bedrock/src/nitro_enclave/tests.rs`), MIT © Tools for Humanity.
//!
//! Licence and copyright notice: see `crypto/NOTICE`.
//!
//! The fixture's certificate chain expired in September 2025, so tests pin `now` to the
//! document's own timestamp, which falls inside its validity window.

// `Duration::from_days` / `from_hours`, which clippy suggests here, are unstable on 1.97.
#![allow(clippy::duration_suboptimal_units)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hex_literal::hex;

use super::{
    AWS_NITRO_ROOT_CERT, EnclaveAttestationError, EnclaveAttestationVerifier, PcrMeasurement,
};

const REAL_ATTESTATION_DOC_BASE64: &str = include_str!("testdata/real_attestation_doc.b64");

/// Ten years, so the fixture is never rejected for staleness.
const GENEROUS_MAX_AGE_MILLIS: u64 = 10 * 365 * 24 * 60 * 60 * 1000;

fn real_document() -> Vec<u8> {
    STANDARD
        .decode(REAL_ATTESTATION_DOC_BASE64.trim())
        .expect("fixture should be valid base64")
}

/// The PCRs the fixture's enclave reported.
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

fn attestation_doc() -> aws_nitro_enclaves_nsm_api::api::AttestationDoc {
    let bytes = real_document();
    let cose = EnclaveAttestationVerifier::parse_cose_sign1(&bytes).expect("fixture should parse");
    EnclaveAttestationVerifier::parse_cbor_payload(&cose).expect("fixture should decode")
}

/// The instant the fixture was produced, so `now` falls inside its certificate window.
fn fixture_instant() -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(attestation_doc().timestamp)
}

#[test]
fn verifies_a_real_attestation_document() {
    let verified = verifier()
        .verify(&real_document(), fixture_instant())
        .expect("the fixture should verify against the pinned AWS root");

    assert!(verified.module_id.contains("-enc"));
    assert_eq!(verified.enclave_public_key.len(), 32);
    assert_eq!(
        verified.pcrs.get(&0).map(Vec::as_slice),
        Some(fixture_pcr_config()[0].value.as_slice())
    );
}

/// Corrupts only the signature: the document still parses and still chains to the AWS root,
/// so this is what proves signature verification actually runs.
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
        .expect_err("a corrupted signature must not verify");

    assert!(
        matches!(
            error,
            EnclaveAttestationError::AttestationSignatureInvalid(_)
        ),
        "expected a signature failure, got: {error}"
    );
}

#[test]
fn rejects_a_document_under_a_different_root() {
    // The fixture's leaf is a valid certificate, but not the AWS root.
    let not_the_root = attestation_doc().certificate.to_vec();

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
fn rejects_measurements_that_match_no_allowed_configuration() {
    let absent_index = {
        // Index 20 is valid but not carried by this document.
        let mut config = fixture_pcr_config();
        config.push(PcrMeasurement::new(20, [0x11u8; 48]));
        vec![config]
    };

    let cases = [
        (
            "a wrong value",
            vec![vec![PcrMeasurement::new(0, [0xabu8; 48])]],
        ),
        ("a pinned index the document omits", absent_index),
        ("nothing pinned at all", Vec::new()),
    ];

    for (label, configs) in cases {
        let error = EnclaveAttestationVerifier::new(configs, GENEROUS_MAX_AGE_MILLIS)
            .verify(&real_document(), fixture_instant())
            .expect_err(&format!("{label} must fail closed"));

        assert!(
            matches!(error, EnclaveAttestationError::CodeUntrusted(_)),
            "{label}: unexpected error: {error}"
        );
    }
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

    assert!(
        matches!(error, EnclaveAttestationError::AttestationStale { .. }),
        "unexpected error: {error}"
    );
}

#[test]
fn rejects_a_document_timestamped_in_the_future() {
    let earlier = fixture_instant() - Duration::from_secs(1);

    let error = verifier()
        .verify(&real_document(), earlier)
        .expect_err("a document from the future must not verify");

    assert!(
        matches!(
            error,
            EnclaveAttestationError::AttestationInvalidTimestamp(_)
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

#[test]
fn rejects_an_empty_configuration_rather_than_matching_it_vacuously() {
    // An empty set of measurements pins nothing, so `all()` over it is vacuously true.
    // Sitting beside a real config it must not become a blanket accept.
    // Paired with a config that does NOT match, so accepting can only come from the empty one.
    let configs = vec![Vec::new(), vec![PcrMeasurement::new(0, [0xabu8; 48])]];

    let error = EnclaveAttestationVerifier::new(configs, GENEROUS_MAX_AGE_MILLIS)
        .verify(&real_document(), fixture_instant())
        .expect_err("an empty configuration must never match");

    assert!(
        matches!(error, EnclaveAttestationError::CodeUntrusted(_)),
        "unexpected error: {error}"
    );
}

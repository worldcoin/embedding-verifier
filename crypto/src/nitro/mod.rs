//! AWS Nitro Enclave attestation verification.
//!
//! Ported from `worldcoin/bedrock` (`bedrock/src/nitro_enclave/mod.rs`), MIT © Tools for
//! Humanity, which ships in World App — the authenticator that calls
//! `POST /v1/enclave-assignment`. Both sides therefore run the same logic rather than two
//! readings of the AWS spec.
//!
//! Follows <https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html#validation-process>
//!
//! Licence and copyright notice: see `crypto/NOTICE`.

use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use coset::{AsCborValue, CoseSign1};
use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use webpki::{EndEntityCert, TrustAnchor};
use x509_cert::{Certificate, der::Decode};

/// Types for enclave verification.
pub mod types;

#[cfg(test)]
mod tests;

pub use types::{
    EnclaveAttestationError, EnclaveAttestationResult, PcrMeasurement, VerifiedAttestation,
};

/// The AWS Nitro Attestation PKI root, from
/// <https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip>.
///
/// Pinned by SHA-256 against the fingerprint AWS publishes for the certificate (not the zip);
/// a test asserts it. Valid until 2049-10-28.
pub const AWS_NITRO_ROOT_CERT: &[u8] = include_bytes!("../../certs/aws_nitro_root_g1.der");

/// Nitro COSE signatures are ECDSA over P-384, so raw `r || s` is always 96 bytes.
const P384_SIGNATURE_LENGTH: usize = 96;

/// Verifies AWS Nitro Enclave attestation documents.
#[derive(Debug, Clone)]
pub struct EnclaveAttestationVerifier {
    allowed_pcr_configs: Vec<Vec<PcrMeasurement>>,
    root_certificate: Cow<'static, [u8]>,
    max_age_millis: u64,
    allow_debug_measurements: bool,
}

impl EnclaveAttestationVerifier {
    /// Creates a verifier trusting any enclave that matches one of `allowed_pcr_configs`.
    ///
    /// `max_age_millis` bounds how old a document's own timestamp may be.
    #[must_use]
    pub const fn new(allowed_pcr_configs: Vec<Vec<PcrMeasurement>>, max_age_millis: u64) -> Self {
        Self {
            allowed_pcr_configs,
            root_certificate: Cow::Borrowed(AWS_NITRO_ROOT_CERT),
            max_age_millis,
            allow_debug_measurements: false,
        }
    }

    /// Accepts enclaves whose measurements are all zero, i.e. run with `--debug-mode`.
    ///
    /// Their memory is readable from the parent instance. Development only.
    #[must_use]
    pub const fn allowing_debug_measurements(mut self) -> Self {
        self.allow_debug_measurements = true;
        self
    }

    /// Replaces the pinned trust anchor. Test-only escape hatch for negative cases.
    #[cfg(test)]
    #[must_use]
    fn with_root_certificate(mut self, root_certificate: Vec<u8>) -> Self {
        self.root_certificate = Cow::Owned(root_certificate);
        self
    }

    /// Verifies a base64-encoded attestation document.
    ///
    /// # Errors
    ///
    /// Returns [`EnclaveAttestationError`] if the input is not valid base64, or if
    /// verification fails for any reason.
    pub fn verify_base64(
        &self,
        attestation_doc_base64: &str,
        now: SystemTime,
    ) -> EnclaveAttestationResult<VerifiedAttestation> {
        let bytes = STANDARD.decode(attestation_doc_base64).map_err(|error| {
            EnclaveAttestationError::AttestationDocumentParseError(format!(
                "failed to decode base64 attestation document: {error}"
            ))
        })?;

        self.verify(&bytes, now)
    }

    /// Verifies a raw COSE-encoded attestation document.
    ///
    /// Fails closed: nothing is returned until the signature, the chain, the measurements and
    /// the freshness all check out.
    ///
    /// # Errors
    ///
    /// Returns [`EnclaveAttestationError`] describing the first check that failed.
    pub fn verify(
        &self,
        attestation_doc_bytes: &[u8],
        now: SystemTime,
    ) -> EnclaveAttestationResult<VerifiedAttestation> {
        let now_millis = unix_millis(now)?;

        // 1. Syntactical validation.
        let cose_sign1 = Self::parse_cose_sign1(attestation_doc_bytes)?;
        let attestation = Self::parse_cbor_payload(&cose_sign1)?;

        // 2. Semantic validation.
        let leaf_cert = self.verify_certificate_chain(&attestation, now_millis)?;

        // 3. Cryptographic validation.
        Self::verify_cose_signature(&cose_sign1, &leaf_cert)?;
        self.validate_pcr_values(&attestation)?;
        self.check_attestation_freshness(&attestation, now_millis)?;
        let public_key = Self::extract_public_key(&attestation)?;

        Ok(VerifiedAttestation {
            enclave_public_key: public_key,
            module_id: attestation.module_id,
            timestamp_millis: attestation.timestamp,
            pcrs: attestation
                .pcrs
                .into_iter()
                .map(|(index, value)| (index, value.into_vec()))
                .collect(),
        })
    }

    fn parse_cose_sign1(bytes: &[u8]) -> EnclaveAttestationResult<CoseSign1> {
        if bytes.is_empty() {
            return Err(EnclaveAttestationError::AttestationDocumentParseError(
                "empty attestation document".to_string(),
            ));
        }

        // Reject anything that is not a CBOR array before handing it to the decoder.
        let first_byte = bytes[0];
        if !(0x80..=0x97).contains(&first_byte) && first_byte != 0x9f {
            return Err(EnclaveAttestationError::AttestationDocumentParseError(
                format!(
                    "invalid CBOR magic byte: expected array marker (0x80-0x97 or 0x9f), got {first_byte:#04x}"
                ),
            ));
        }

        let cbor_value: ciborium::Value = ciborium::from_reader(bytes).map_err(|error| {
            EnclaveAttestationError::AttestationDocumentParseError(format!(
                "failed to parse CBOR: {error}"
            ))
        })?;

        CoseSign1::from_cbor_value(cbor_value).map_err(|error| {
            EnclaveAttestationError::AttestationDocumentParseError(format!(
                "failed to parse COSE Sign1: {error}"
            ))
        })
    }

    fn parse_cbor_payload(cose_sign1: &CoseSign1) -> EnclaveAttestationResult<AttestationDoc> {
        let payload = cose_sign1.payload.as_ref().ok_or_else(|| {
            EnclaveAttestationError::AttestationDocumentParseError(
                "missing payload in COSE Sign1".to_string(),
            )
        })?;

        ciborium::from_reader::<AttestationDoc, _>(payload.as_slice()).map_err(|error| {
            EnclaveAttestationError::AttestationDocumentParseError(format!(
                "failed to parse attestation document: {error}"
            ))
        })
    }

    /// Validates the chain from the leaf up to the pinned root and returns the leaf.
    ///
    /// `cabundle` is root-first, so element 0 is the root we already pin. The TLS-server
    /// entry point is webpki 0.22's only chain validator; it also requires the `serverAuth`
    /// EKU, which Nitro leaf certificates carry. No DNS name is checked.
    fn verify_certificate_chain(
        &self,
        attestation: &AttestationDoc,
        now_millis: u64,
    ) -> EnclaveAttestationResult<Certificate> {
        let trust_anchor =
            TrustAnchor::try_from_cert_der(self.root_certificate.as_ref()).map_err(|error| {
                EnclaveAttestationError::AttestationChainInvalid(format!(
                    "failed to create trust anchor from root certificate: {error}"
                ))
            })?;

        let intermediate_certs: Vec<&[u8]> = attestation
            .cabundle
            .iter()
            .skip(1)
            .map(|cert| cert.as_slice())
            .collect();

        let end_entity_cert =
            EndEntityCert::try_from(attestation.certificate.as_slice()).map_err(|error| {
                EnclaveAttestationError::AttestationChainInvalid(format!(
                    "failed to parse leaf certificate: {error}"
                ))
            })?;

        end_entity_cert
            .verify_is_valid_tls_server_cert(
                &[&webpki::ECDSA_P384_SHA384],
                &webpki::TlsServerTrustAnchors(&[trust_anchor]),
                &intermediate_certs,
                webpki::Time::from_seconds_since_unix_epoch(now_millis / 1_000),
            )
            .map_err(|error| {
                EnclaveAttestationError::AttestationChainInvalid(format!(
                    "certificate chain validation failed: {error}"
                ))
            })?;

        Certificate::from_der(&attestation.certificate).map_err(|error| {
            EnclaveAttestationError::AttestationChainInvalid(format!(
                "failed to parse leaf certificate for return: {error}"
            ))
        })
    }

    fn verify_cose_signature(
        cose_sign1: &CoseSign1,
        leaf_cert: &Certificate,
    ) -> EnclaveAttestationResult<()> {
        let spki = &leaf_cert.tbs_certificate.subject_public_key_info;
        let public_key_bytes = spki.subject_public_key.as_bytes().ok_or_else(|| {
            EnclaveAttestationError::AttestationSignatureInvalid(
                "failed to extract public key bytes".to_string(),
            )
        })?;

        let verifying_key = VerifyingKey::from_sec1_bytes(public_key_bytes).map_err(|error| {
            EnclaveAttestationError::AttestationSignatureInvalid(format!(
                "failed to parse P-384 public key: {error}"
            ))
        })?;

        let signature = &cose_sign1.signature;
        if signature.len() != P384_SIGNATURE_LENGTH {
            return Err(EnclaveAttestationError::AttestationSignatureInvalid(
                format!(
                    "invalid signature length: expected {P384_SIGNATURE_LENGTH} bytes, got {}",
                    signature.len()
                ),
            ));
        }

        // Sig_structure per RFC 8152 §4.4, with no external AAD.
        let sig_structure = cose_sign1.tbs_data(&[]);

        let ecdsa_signature = Signature::try_from(signature.as_slice()).map_err(|error| {
            EnclaveAttestationError::AttestationSignatureInvalid(format!(
                "failed to parse ECDSA signature (need {P384_SIGNATURE_LENGTH} raw bytes): {error}"
            ))
        })?;

        verifying_key
            .verify(&sig_structure, &ecdsa_signature)
            .map_err(|error| {
                EnclaveAttestationError::AttestationSignatureInvalid(format!(
                    "signature verification failed: {error}"
                ))
            })
    }

    fn validate_pcr_values(&self, attestation: &AttestationDoc) -> EnclaveAttestationResult<()> {
        if attestation.pcrs.is_empty() {
            return Err(EnclaveAttestationError::CodeUntrusted(
                "document carries no PCRs".to_string(),
            ));
        }

        if !self.allow_debug_measurements
            && attestation
                .pcrs
                .values()
                .all(|value| value.iter().all(|byte| *byte == 0))
        {
            return Err(EnclaveAttestationError::DebugMeasurements);
        }

        if self.allowed_pcr_configs.is_empty() {
            return Err(EnclaveAttestationError::CodeUntrusted(
                "no allowed PCR configurations".to_string(),
            ));
        }

        let expected_pcr_length = expected_pcr_length(attestation.digest);

        for allowed_pcr_measurements in &self.allowed_pcr_configs {
            // `all()` is vacuously true over an empty set, which would accept any enclave.
            if allowed_pcr_measurements.is_empty() {
                continue;
            }

            let all_match = allowed_pcr_measurements.iter().all(|measurement| {
                attestation
                    .pcrs
                    .get(&(measurement.index as usize))
                    .is_some_and(|value| {
                        value.len() == expected_pcr_length
                            && value.as_slice() == measurement.value.as_slice()
                    })
            });

            if all_match {
                return Ok(());
            }
        }

        Err(EnclaveAttestationError::CodeUntrusted(
            "no allowed PCR configuration matched".to_string(),
        ))
    }

    fn check_attestation_freshness(
        &self,
        attestation: &AttestationDoc,
        now_millis: u64,
    ) -> EnclaveAttestationResult<()> {
        let age = now_millis
            .checked_sub(attestation.timestamp)
            .ok_or_else(|| {
                EnclaveAttestationError::AttestationInvalidTimestamp(format!(
                    "attestation timestamp is {}ms in the future",
                    attestation.timestamp.saturating_sub(now_millis)
                ))
            })?;

        if age > self.max_age_millis {
            return Err(EnclaveAttestationError::AttestationStale {
                age_millis: age,
                max_age: self.max_age_millis,
            });
        }

        Ok(())
    }

    fn extract_public_key(attestation: &AttestationDoc) -> EnclaveAttestationResult<Vec<u8>> {
        let key = attestation.public_key.as_ref().ok_or_else(|| {
            EnclaveAttestationError::InvalidEnclavePublicKey(
                "no public key in attestation document".to_string(),
            )
        })?;

        Ok(key.to_vec())
    }
}

/// Expected PCR length for the digest the document says it used.
const fn expected_pcr_length(digest: aws_nitro_enclaves_nsm_api::api::Digest) -> usize {
    use aws_nitro_enclaves_nsm_api::api::Digest;

    match digest {
        Digest::SHA256 => 32,
        Digest::SHA384 => 48,
        Digest::SHA512 => 64,
    }
}

/// Converts a wall-clock instant to milliseconds since the Unix epoch.
fn unix_millis(now: SystemTime) -> EnclaveAttestationResult<u64> {
    let millis = now
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            EnclaveAttestationError::AttestationInvalidTimestamp(format!(
                "clock is before the Unix epoch: {error}"
            ))
        })?
        .as_millis();

    u64::try_from(millis).map_err(|error| {
        EnclaveAttestationError::AttestationInvalidTimestamp(format!(
            "clock does not fit in milliseconds since the epoch: {error}"
        ))
    })
}

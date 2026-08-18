//! Nitro Secure Module attestation.
//!
//! Attestation is the only thing that makes an enclave's public keys trustworthy, so a
//! module that cannot attest is treated as a failed boot rather than a per-request error.
//! Verification is deliberately absent: the COSE signature, the certificate chain to the
//! AWS Nitro root, and the expected PCRs are all checked client-side.

use enclave_types::EnclaveError;
use pontifex::{AttestationDoc, SecureModule};

/// Produces attestation documents binding a public key to this enclave.
///
/// A trait so handlers never reach for the NSM global, and so tests can exercise the
/// attestation paths without a `/dev/nsm` device.
pub trait Attestor: Send + Sync {
    /// Attests `public_key` in the document's `public_key` field.
    ///
    /// No `nonce` and no `user_data`: the document asserts that a key was generated
    /// inside an enclave running a given image, which is time-invariant, and certificate
    /// validity already bounds how long a document can be replayed.
    ///
    /// # Errors
    ///
    /// Returns [`EnclaveError::AttestationFailed`] when the module rejects the request.
    fn attest_public_key(&self, public_key: &[u8]) -> Result<Vec<u8>, EnclaveError>;
}

/// [`Attestor`] backed by the real Nitro Secure Module.
#[derive(Debug, Clone, Copy)]
pub struct NsmAttestor;

impl Attestor for NsmAttestor {
    fn attest_public_key(&self, public_key: &[u8]) -> Result<Vec<u8>, EnclaveError> {
        let secure_module =
            SecureModule::try_global().ok_or(EnclaveError::SecureModuleNotInitialized)?;

        secure_module
            .raw_attest(None::<Vec<u8>>, None::<Vec<u8>>, Some(public_key.to_vec()))
            .map_err(|error| {
                tracing::error!(?error, "failed to attest public key");
                EnclaveError::AttestationFailed
            })
    }
}

/// Connects to the Nitro Secure Module.
///
/// Called before serving so a missing or broken device fails the boot. Pontifex
/// otherwise initialises the module inside its accept loop, which would leave the whole
/// pre-serve window unable to attest and surface the failure only once traffic arrives.
/// The initialisation is idempotent, so Pontifex's own call becomes a no-op.
///
/// # Errors
///
/// Returns an error when the NSM device cannot be opened.
pub async fn connect() -> anyhow::Result<&'static SecureModule> {
    Ok(SecureModule::try_init_global().await?)
}

/// Whether every PCR in a document is zeroed.
///
/// True for a `--debug-mode` enclave, whose measurements say nothing about the image
/// that produced them.
#[must_use]
pub fn has_zeroed_measurements(document: &AttestationDoc) -> bool {
    !document.pcrs.is_empty()
        && document
            .pcrs
            .values()
            .all(|pcr| pcr.iter().all(|&b| b == 0))
}

/// Logs the measurements a client will pin this enclave against.
///
/// Emitted once at boot so the running image is identifiable from logs alone, without
/// an attestation fetch.
pub fn log_boot_measurements(document: &AttestationDoc) {
    let pcr0 = document.pcrs.get(&0).map(hex::encode).unwrap_or_default();

    if has_zeroed_measurements(document) {
        tracing::warn!(
            module_id = %document.module_id,
            "enclave is running in debug mode: measurements are zeroed and attestations \
             are not verifiable against a released image"
        );
    } else {
        tracing::info!(module_id = %document.module_id, pcr0 = %pcr0, "attested enclave measurements");
    }
}

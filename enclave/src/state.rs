//! Boot-scoped state owned by the enclave.

use std::sync::Arc;

use crypto::match_token::{MatchTokenSigner, SIGNING_KEY_LEN};
use crypto::sealed_channel::{ENCRYPTION_KEY_LEN, Responder, UnwrapErr};
use enclave_types::EnclaveError;
use getrandom::SysRng;

use crate::{attestation::Attestor, face_engine::FaceComparator};

/// Immutable state generated once during enclave boot.
pub struct EnclaveState {
    responder: Responder,
    match_token_signer: MatchTokenSigner,
    attestor: Arc<dyn Attestor>,
    face_engine: Arc<dyn FaceComparator>,
}

impl EnclaveState {
    /// Generates fresh boot-scoped keys, with the provided attestor and Face Engine.
    #[must_use]
    pub fn generate(attestor: Arc<dyn Attestor>, face_engine: Arc<dyn FaceComparator>) -> Self {
        let mut channel_rng = UnwrapErr(SysRng);
        let responder = Responder::generate(&mut channel_rng);
        // The signer draws from rand's OsRng rather than SysRng because eddsa-babyjubjub speaks
        // the rand 0.8 trait family, not the rand_core 0.10 one hpke uses. Both name the same OS
        // entropy source, which inside an enclave is the boot-verified Nitro hardware RNG.
        let match_token_signer = MatchTokenSigner::generate(&mut rand::rngs::OsRng);
        tracing::info!("generated boot-scoped sealed channel and signing keys");

        Self {
            responder,
            match_token_signer,
            attestor,
            face_engine,
        }
    }

    /// Returns the responder that opens sealed requests for this boot.
    #[must_use]
    pub const fn responder(&self) -> &Responder {
        &self.responder
    }

    /// Returns the X25519 public key attested for this enclave boot.
    #[must_use]
    pub const fn encryption_public_key(&self) -> [u8; ENCRYPTION_KEY_LEN] {
        self.responder.public_key()
    }

    /// Returns the match-token signer for this boot.
    #[must_use]
    pub const fn match_token_signer(&self) -> &MatchTokenSigner {
        &self.match_token_signer
    }

    /// Returns the compressed `BabyJubJub` public key that verifies this boot's match tokens.
    #[must_use]
    pub const fn signing_public_key(&self) -> [u8; SIGNING_KEY_LEN] {
        self.match_token_signer.public_key()
    }

    /// Returns the Face Engine used for enclave match operations.
    #[must_use]
    pub fn face_engine(&self) -> &dyn FaceComparator {
        self.face_engine.as_ref()
    }

    /// Attests the encryption public key.
    ///
    /// # Errors
    ///
    /// Propagates the [`Attestor`] failure.
    pub fn attest_encryption_key(&self) -> Result<Vec<u8>, EnclaveError> {
        self.attestor
            .attest_public_key(&self.encryption_public_key())
    }

    /// Attests the signing public key.
    ///
    /// # Errors
    ///
    /// Propagates the [`Attestor`] failure. Serializing the key cannot fail here: it is derived
    /// once when the signer is generated, so a key that would not serialize fails the boot instead.
    pub fn attest_signing_key(&self) -> Result<Vec<u8>, EnclaveError> {
        self.attestor.attest_public_key(&self.signing_public_key())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::EnclaveState;
    use crate::test_support::{EchoAttestor, state_with};

    fn state() -> Arc<EnclaveState> {
        state_with(Arc::new(EchoAttestor))
    }

    #[test]
    fn keys_are_stable_for_one_state() {
        let state = state();

        assert_eq!(state.encryption_public_key(), state.encryption_public_key());
        assert_eq!(state.signing_public_key(), state.signing_public_key());
    }

    #[test]
    fn separate_states_receive_separate_keys() {
        let first = state();
        let second = state();

        assert_ne!(
            first.encryption_public_key(),
            second.encryption_public_key()
        );
        assert_ne!(first.signing_public_key(), second.signing_public_key());
    }

    #[test]
    fn each_key_is_attested_in_its_own_document() {
        let state = state();

        assert_eq!(
            state.attest_encryption_key(),
            Ok(state.encryption_public_key().to_vec())
        );
        assert_eq!(
            state.attest_signing_key(),
            Ok(state.signing_public_key().to_vec())
        );
    }
}

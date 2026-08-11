//! Boot-scoped state owned by the secure enclave.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead as _, Key, Nonce},
};
use enclave_types::{
    AEAD_TAG_LEN, CHANNEL_VERSION, ENCAPPED_KEY_LEN, EnclaveError, RESPONSE_KEY_LABEL,
    RESPONSE_KEY_LEN, RESPONSE_NONCE_LABEL, RESPONSE_NONCE_LEN, channel_info,
};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, Serializable, aead::AeadCtxR, setup_receiver,
};
use zeroize::Zeroize;

/// The channel ciphersuite, pinned at the type level so it cannot drift silently:
/// DHKEM(X25519, HKDF-SHA256) — RFC 9180 §7.1.
type Kem = hpke::kem::X25519HkdfSha256;
/// HKDF-SHA256 — RFC 9180 §7.2.
type Kdf = hpke::kdf::HkdfSha256;
/// ChaCha20-Poly1305 — RFC 9180 §7.3.
type Aead = hpke::aead::ChaCha20Poly1305;

/// The HPKE receiver context for one request.
type RequestContext = AeadCtxR<Aead, Kdf, Kem>;

/// Immutable state generated once during enclave boot.
pub struct EnclaveState {
    transit_secret_key: <Kem as KemTrait>::PrivateKey,
    transit_public_key: [u8; 32],
}

impl EnclaveState {
    /// Generates fresh boot-scoped enclave state using the operating-system RNG.
    ///
    /// # Panics
    ///
    /// Panics if the generated X25519 public key is not 32 bytes, which the KEM
    /// definition makes impossible.
    #[must_use]
    pub fn generate() -> Self {
        let (transit_secret_key, public_key) = Kem::gen_keypair();
        let transit_public_key = public_key
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("X25519 public keys are 32 bytes");

        tracing::info!("generated boot-scoped transit key");

        Self {
            transit_secret_key,
            transit_public_key,
        }
    }

    /// Returns the X25519 public key clients encrypt to for this enclave boot.
    #[must_use]
    pub const fn transit_public_key(&self) -> [u8; 32] {
        self.transit_public_key
    }

    /// Opens an HPKE request addressed to this boot's transit public key.
    ///
    /// Splits the raw `enc || ciphertext` body, then runs `SetupBaseR` (RFC 9180
    /// §5.1.1) against the client's encapsulated key and opens the ciphertext. Base mode
    /// means the sender is anonymous — by design, as callers are not pre-registered and
    /// provenance is enforced downstream, not here.
    ///
    /// Returns the plaintext together with a [`ResponseSealer`] derived from the *same*
    /// context, which is what makes the reply readable only by this request's sender
    /// (RFC 9180 §9.8).
    ///
    /// # Errors
    ///
    /// Returns [`EnclaveError::BadRequest`] when the body is too short, the encapsulated
    /// key is malformed or yields the all-zero shared secret (RFC 9180 §7.1.4, enforced
    /// by the KEM), or the ciphertext fails authentication. The error is deliberately
    /// opaque: no plaintext, ciphertext, or key material is surfaced or logged.
    pub fn open_request(&self, body: &[u8]) -> Result<(Vec<u8>, ResponseSealer), EnclaveError> {
        if body.len() <= ENCAPPED_KEY_LEN + AEAD_TAG_LEN {
            return Err(EnclaveError::BadRequest);
        }
        let (enc, ciphertext) = body.split_at(ENCAPPED_KEY_LEN);

        let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(enc)
            .map_err(|_| EnclaveError::BadRequest)?;

        let info = channel_info(CHANNEL_VERSION, &self.transit_public_key);
        let mut context = setup_receiver::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &self.transit_secret_key,
            &encapped_key,
            &info,
        )
        .map_err(|_| EnclaveError::BadRequest)?;

        // The request carries nothing outside the ciphertext that the host could swap:
        // `enc` is already bound into the key schedule by the KEM.
        let plaintext = context
            .open(ciphertext, &[])
            .map_err(|_| EnclaveError::BadRequest)?;

        let sealer = ResponseSealer::derive(&context)?;

        Ok((plaintext, sealer))
    }
}

/// A single-use AEAD sealer for the response half of one request's HPKE context.
///
/// RFC 9180 §9.8: the key and nonce are exported from the request context rather than
/// reusing that context in the opposite direction, which the RFC forbids. Both sides
/// derive them independently, so nothing but the ciphertext goes on the wire.
pub struct ResponseSealer {
    key: [u8; RESPONSE_KEY_LEN],
    nonce: [u8; RESPONSE_NONCE_LEN],
}

impl ResponseSealer {
    /// Derives the response key and nonce from a request context.
    fn derive(context: &RequestContext) -> Result<Self, EnclaveError> {
        let mut key = [0u8; RESPONSE_KEY_LEN];
        let mut nonce = [0u8; RESPONSE_NONCE_LEN];

        context
            .export(RESPONSE_KEY_LABEL, &mut key)
            .and_then(|()| context.export(RESPONSE_NONCE_LABEL, &mut nonce))
            .map_err(|error| {
                tracing::error!(?error, "failed to export response key material");
                EnclaveError::Internal
            })?;

        Ok(Self { key, nonce })
    }

    /// Seals `plaintext` under the exported key, binding `aad`.
    ///
    /// Consumes `self`: the exported (key, nonce) pair is fixed for the lifetime of a
    /// context, so a second seal under it would reuse the nonce. Taking ownership makes
    /// that a compile error rather than a review item.
    ///
    /// # Errors
    ///
    /// Returns [`EnclaveError::Internal`] when the AEAD fails, which for a well-formed
    /// key, nonce, and in-memory plaintext should not happen.
    pub fn seal(self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, EnclaveError> {
        let key =
            Key::<ChaCha20Poly1305>::try_from(&self.key[..]).map_err(|_| EnclaveError::Internal)?;
        let nonce = Nonce::<ChaCha20Poly1305>::try_from(&self.nonce[..])
            .map_err(|_| EnclaveError::Internal)?;

        ChaCha20Poly1305::new(&key)
            .encrypt(
                &nonce,
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| {
                tracing::error!("failed to seal match response");
                EnclaveError::Internal
            })
    }
}

impl Drop for ResponseSealer {
    fn drop(&mut self) {
        self.key.zeroize();
        self.nonce.zeroize();
    }
}

#[cfg(test)]
pub(crate) mod test_client {
    //! A minimal client-side half of the channel, used to drive the enclave in tests.

    use chacha20poly1305::{
        ChaCha20Poly1305, KeyInit,
        aead::{Aead as _, Key, Nonce},
    };
    use enclave_types::{
        CHANNEL_VERSION, RESPONSE_KEY_LABEL, RESPONSE_KEY_LEN, RESPONSE_NONCE_LABEL,
        RESPONSE_NONCE_LEN, channel_info,
    };
    use hpke::{
        Deserializable, Kem as KemTrait, OpModeS, Serializable, aead::AeadCtxS, setup_sender,
    };

    use super::{Aead, Kdf, Kem};

    /// The client's side of one HPKE channel.
    pub struct ClientChannel {
        context: AeadCtxS<Aead, Kdf, Kem>,
    }

    impl ClientChannel {
        /// Runs `SetupBaseS` against an enclave's advertised transit key and seals
        /// `plaintext`, returning the raw wire body `enc || ciphertext`.
        pub fn seal(transit_public_key: &[u8; 32], plaintext: &[u8]) -> (Self, Vec<u8>) {
            Self::seal_with_info(
                transit_public_key,
                plaintext,
                &channel_info(CHANNEL_VERSION, transit_public_key),
            )
        }

        /// As [`Self::seal`], but with a caller-chosen `info` so tests can prove the
        /// binding actually bites.
        pub fn seal_with_info(
            transit_public_key: &[u8; 32],
            plaintext: &[u8],
            info: &[u8],
        ) -> (Self, Vec<u8>) {
            let public_key = <Kem as KemTrait>::PublicKey::from_bytes(transit_public_key)
                .expect("transit key should deserialize");

            let (enc, mut context) =
                setup_sender::<Aead, Kdf, Kem>(&OpModeS::Base, &public_key, info)
                    .expect("sender setup should succeed");
            let ciphertext = context.seal(plaintext, &[]).expect("seal should succeed");
            let mut body = enc.to_bytes().to_vec();
            body.extend_from_slice(&ciphertext);

            (Self { context }, body)
        }

        /// Opens a response sealed to this channel (RFC 9180 §9.8).
        pub fn open_response(&self, ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
            let mut key_bytes = [0u8; RESPONSE_KEY_LEN];
            let mut nonce_bytes = [0u8; RESPONSE_NONCE_LEN];
            self.context
                .export(RESPONSE_KEY_LABEL, &mut key_bytes)
                .ok()?;
            self.context
                .export(RESPONSE_NONCE_LABEL, &mut nonce_bytes)
                .ok()?;

            let key = Key::<ChaCha20Poly1305>::try_from(&key_bytes[..]).ok()?;
            let nonce = Nonce::<ChaCha20Poly1305>::try_from(&nonce_bytes[..]).ok()?;

            ChaCha20Poly1305::new(&key)
                .decrypt(
                    &nonce,
                    chacha20poly1305::aead::Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use enclave_types::{
        AEAD_TAG_LEN, CHANNEL_VERSION, ENCAPPED_KEY_LEN, EnclaveError, channel_info,
    };

    use super::{EnclaveState, test_client::ClientChannel};

    #[test]
    fn transit_key_is_stable_for_one_state() {
        let state = EnclaveState::generate();

        assert_eq!(state.transit_public_key(), state.transit_public_key());
    }

    #[test]
    fn separate_states_receive_separate_transit_keys() {
        let first = EnclaveState::generate();
        let second = EnclaveState::generate();

        assert_ne!(first.transit_public_key(), second.transit_public_key());
    }

    #[test]
    fn opens_a_request_sealed_to_the_transit_key() {
        let state = EnclaveState::generate();
        let (_, body) = ClientChannel::seal(&state.transit_public_key(), b"inputs");

        let (plaintext, _) = state
            .open_request(&body)
            .expect("a well-formed request should open");

        assert_eq!(plaintext, b"inputs");
    }

    #[test]
    fn response_key_material_agrees_across_the_channel() {
        let state = EnclaveState::generate();
        let (client, body) = ClientChannel::seal(&state.transit_public_key(), b"inputs");
        let (_, sealer) = state.open_request(&body).expect("should open");

        let response = sealer
            .seal(b"statement", b"\x01")
            .expect("sealing should succeed");

        assert_eq!(
            client.open_response(&response, b"\x01").as_deref(),
            Some(&b"statement"[..])
        );
    }

    #[test]
    fn rejects_a_request_sealed_to_another_boot() {
        let state = EnclaveState::generate();
        let other = EnclaveState::generate();
        let (_, body) = ClientChannel::seal(&other.transit_public_key(), b"inputs");

        assert_eq!(
            state.open_request(&body).err(),
            Some(EnclaveError::BadRequest)
        );
    }

    #[test]
    fn rejects_a_request_bound_to_another_channel_version() {
        let state = EnclaveState::generate();
        let transit_public_key = state.transit_public_key();
        let (_, body) = ClientChannel::seal_with_info(
            &transit_public_key,
            b"inputs",
            &channel_info(CHANNEL_VERSION + 1, &transit_public_key),
        );

        assert_eq!(
            state.open_request(&body).err(),
            Some(EnclaveError::BadRequest)
        );
    }

    #[test]
    fn rejects_a_low_order_encapsulated_key() {
        // RFC 9180 §7.1.4: an all-zero X25519 shared secret must abort.
        let state = EnclaveState::generate();
        let (_, mut body) = ClientChannel::seal(&state.transit_public_key(), b"inputs");
        body[..ENCAPPED_KEY_LEN].fill(0);

        let result = state.open_request(&body);

        assert_eq!(result.err(), Some(EnclaveError::BadRequest));
    }

    #[test]
    fn rejects_a_short_sealed_body() {
        let state = EnclaveState::generate();

        for length in [0, ENCAPPED_KEY_LEN, ENCAPPED_KEY_LEN + AEAD_TAG_LEN] {
            assert_eq!(
                state.open_request(&vec![0u8; length]).err(),
                Some(EnclaveError::BadRequest),
                "length {length}"
            );
        }
    }

    #[test]
    fn rejects_a_tampered_request_ciphertext() {
        let state = EnclaveState::generate();
        let (_, mut body) = ClientChannel::seal(&state.transit_public_key(), b"inputs");
        body[ENCAPPED_KEY_LEN] ^= 0x01;

        let result = state.open_request(&body);

        assert_eq!(result.err(), Some(EnclaveError::BadRequest));
    }
}

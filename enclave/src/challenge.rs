//! Decrypting the RP's challenge image.
//!
//! The key travels sealed inside the match request, so a blob the host substituted fails closed
//! here. Format fixed by what the RP writes: AES-256-GCM, 32-byte key, separate 12-byte IV, over
//! `ciphertext || tag`.

use aes_gcm::{
    Aes256Gcm, Key, KeyInit,
    aead::{Aead, Nonce},
};
use crypto::payload::{CHALLENGE_IV_LEN, CHALLENGE_KEY_LEN};
use enclave_types::EnclaveError;

/// Decrypts the challenge image with the key and IV that arrived sealed.
///
/// # Errors
///
/// Returns [`EnclaveError::ChallengeDecryptFailed`] if the blob does not authenticate. None of the
/// causes is a face failing.
pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8; CHALLENGE_KEY_LEN],
    iv: &[u8; CHALLENGE_IV_LEN],
) -> Result<Vec<u8>, EnclaveError> {
    Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key))
        .decrypt(&Nonce::<Aes256Gcm>::from(*iv), ciphertext)
        .map_err(|_| {
            tracing::warn!("challenge image failed to decrypt");
            EnclaveError::ChallengeDecryptFailed
        })
}

#[cfg(test)]
mod tests {
    use aes_gcm::{
        Aes256Gcm, Key, KeyInit,
        aead::{Aead, Nonce},
    };
    use crypto::payload::{CHALLENGE_IV_LEN, CHALLENGE_KEY_LEN};
    use enclave_types::EnclaveError;

    use super::decrypt;

    const KEY: [u8; CHALLENGE_KEY_LEN] = [7u8; CHALLENGE_KEY_LEN];
    const IV: [u8; CHALLENGE_IV_LEN] = [9u8; CHALLENGE_IV_LEN];

    /// Encrypts the way the RP does: AES-256-GCM, key and IV separate, `ciphertext || tag`.
    fn encrypt(
        plaintext: &[u8],
        key: &[u8; CHALLENGE_KEY_LEN],
        iv: &[u8; CHALLENGE_IV_LEN],
    ) -> Vec<u8> {
        Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key))
            .encrypt(&Nonce::<Aes256Gcm>::from(*iv), plaintext)
            .expect("encryption should succeed")
    }

    #[test]
    fn round_trips_an_rp_shaped_blob() {
        let blob = encrypt(b"challenge-frame", &KEY, &IV);

        assert_eq!(
            decrypt(&blob, &KEY, &IV).expect("should decrypt"),
            b"challenge-frame"
        );
    }

    #[test]
    fn rejects_the_wrong_key() {
        // Also what a host swapping the fetched object looks like from in here.
        let blob = encrypt(b"challenge-frame", &KEY, &IV);

        assert_eq!(
            decrypt(&blob, &[8u8; CHALLENGE_KEY_LEN], &IV).err(),
            Some(EnclaveError::ChallengeDecryptFailed)
        );
    }

    #[test]
    fn rejects_the_wrong_iv() {
        let blob = encrypt(b"challenge-frame", &KEY, &IV);

        assert_eq!(
            decrypt(&blob, &KEY, &[10u8; CHALLENGE_IV_LEN]).err(),
            Some(EnclaveError::ChallengeDecryptFailed)
        );
    }

    #[test]
    fn rejects_a_truncated_tag() {
        let mut blob = encrypt(b"challenge-frame", &KEY, &IV);
        blob.pop();

        assert_eq!(
            decrypt(&blob, &KEY, &IV).err(),
            Some(EnclaveError::ChallengeDecryptFailed)
        );
    }
}

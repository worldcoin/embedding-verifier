//! Decrypting the RP's challenge image.
//!
//! The RP encrypts the challenge frame, uploads the ciphertext to S3, and sends the key to the
//! authenticator, which seals it into the match request. The host fetches the blob but holds no key
//! for it, so a substituted URL or a swapped blob fails closed here.
//!
//! The format is fixed by what the RP already writes: AES-256-GCM, 32-byte key, 12-byte IV stored
//! separately, over a blob of `ciphertext || tag`.

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
/// Returns [`EnclaveError::ChallengeDecryptFailed`] if the blob does not authenticate under the
/// supplied key and IV. A wrong key, a truncated tag and a substituted blob are indistinguishable
/// here, and none of them is a face failing.
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

    #[test]
    fn rejects_a_substituted_blob() {
        // What a host swapping the fetched object looks like from in here.
        let blob = encrypt(b"a-different-frame", &[1u8; CHALLENGE_KEY_LEN], &IV);

        assert_eq!(
            decrypt(&blob, &KEY, &IV).err(),
            Some(EnclaveError::ChallengeDecryptFailed)
        );
    }
}

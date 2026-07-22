use std::sync::Arc;

use enclave_types::{BindPcpRequest, BindPcpResponse, EnclaveError};
use pontifex::Request;

use crate::pcp::{self, SealedPcpPayload};
use crate::state::EnclaveState;

pub async fn handler(
    state: Arc<EnclaveState>,
    request: BindPcpRequest,
) -> Result<BindPcpResponse, EnclaveError> {
    let plaintext = state.unseal(&request.sealed_payload).inspect_err(|error| {
        tracing::warn!(
            ?error,
            route = BindPcpRequest::ROUTE_ID,
            "failed to unseal request"
        );
    })?;

    let payload = SealedPcpPayload::from_cbor(&plaintext).inspect_err(|error| {
        tracing::warn!(
            ?error,
            route = BindPcpRequest::ROUTE_ID,
            "malformed pcp payload"
        );
    })?;

    let credential_claim = pcp::verify_pcp(&payload.credential_image, &payload.hashes_json)
        .inspect_err(|error| {
            tracing::warn!(
                ?error,
                route = BindPcpRequest::ROUTE_ID,
                "pcp binding rejected"
            );
        })?;

    Ok(BindPcpResponse { credential_claim })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crypto_box::{PublicKey, aead::OsRng};
    use enclave_types::{BindPcpRequest, EnclaveError};
    use sha2::{Digest, Sha256};

    use super::handler;
    use crate::pcp::SealedPcpPayload;
    use crate::state::EnclaveState;

    fn seal_to(state: &EnclaveState, plaintext: &[u8]) -> Vec<u8> {
        let public_key = PublicKey::from(state.transit_public_key());
        public_key
            .seal(&mut OsRng, plaintext)
            .expect("sealing should succeed")
    }

    fn seal_payload(state: &EnclaveState, image: &[u8], hashes_json: &[u8]) -> Vec<u8> {
        let payload = SealedPcpPayload {
            credential_image: image.to_vec(),
            hashes_json: hashes_json.to_vec(),
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&payload, &mut cbor).expect("cbor encoding should succeed");
        seal_to(state, &cbor)
    }

    fn hashes_json_for(image: &[u8]) -> Vec<u8> {
        let hash = hex::encode(Sha256::digest(image));
        format!(r#"{{"thumbnail.png":"{hash}"}}"#).into_bytes()
    }

    #[tokio::test]
    async fn handler_binds_valid_sealed_payload() {
        let state = Arc::new(EnclaveState::generate());
        let image = b"credential-thumbnail";
        let hashes_json = hashes_json_for(image);
        let sealed_payload = seal_payload(&state, image, &hashes_json);

        let response = handler(state, BindPcpRequest { sealed_payload })
            .await
            .expect("binding should succeed");

        assert_eq!(
            response.credential_claim,
            Sha256::digest(&hashes_json).as_slice()
        );
    }

    #[tokio::test]
    async fn handler_rejects_undecryptable_payload() {
        let state = Arc::new(EnclaveState::generate());

        let result = handler(
            state,
            BindPcpRequest {
                sealed_payload: vec![0u8; 64],
            },
        )
        .await;

        assert_eq!(result, Err(EnclaveError::DecryptFailed));
    }

    #[tokio::test]
    async fn handler_rejects_non_cbor_plaintext() {
        let state = Arc::new(EnclaveState::generate());
        let sealed_payload = seal_to(&state, b"not cbor framing");

        let result = handler(state, BindPcpRequest { sealed_payload }).await;

        assert_eq!(result, Err(EnclaveError::MalformedPcpPayload));
    }

    #[tokio::test]
    async fn handler_rejects_mismatched_thumbnail() {
        let state = Arc::new(EnclaveState::generate());
        let hashes_json = hashes_json_for(b"the-enrolled-image");
        let sealed_payload = seal_payload(&state, b"a-different-image", &hashes_json);

        let result = handler(state, BindPcpRequest { sealed_payload }).await;

        assert_eq!(result, Err(EnclaveError::ThumbnailHashMismatch));
    }
}

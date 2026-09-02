use serde::{Deserialize, Serialize};

/// `POST /v1/enclave-assignment` response.
///
/// The enclave assigned to a client, as an attestation document. The document already carries
/// the enclave's identity, measurements and expiry, and the client verifies it before trusting
/// any of them, so the host relays opaque bytes and adds no fields of its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnclaveAssignmentResponse {
    /// The encryption-key attestation, base64.
    pub attestation: String,
}

#[cfg(test)]
mod tests {
    use super::EnclaveAssignmentResponse;

    #[test]
    fn the_response_keeps_its_wire_name() {
        let body = EnclaveAssignmentResponse {
            attestation: "Y29zZQ==".to_owned(),
        };
        let json = serde_json::json!({ "attestation": "Y29zZQ==" });

        assert_eq!(serde_json::to_value(&body).expect("should serialize"), json);
        assert_eq!(
            serde_json::from_value::<EnclaveAssignmentResponse>(json).expect("should deserialize"),
            body
        );
    }
}

use serde::{Deserialize, Serialize};

/// `POST /v1/matches` request.
///
/// `challenge_image_id` is plaintext so the host can start the fetch immediately; `ciphertext`
/// is the sealed request, which the host relays without being able to read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchRequestBody {
    /// Which object in the host's configured bucket holds the encrypted challenge image.
    pub challenge_image_id: String,
    /// The sealed match request, base64.
    pub ciphertext: String,
}

/// `POST /v1/matches` response.
///
/// Both fields are opaque to the host. There is deliberately no cleartext outcome: whether a
/// match held is itself a fact about the request, so the host learns only that the enclave
/// answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchResponseBody {
    /// The sealed outcome, base64.
    pub response_ciphertext: String,
    /// The signing-key attestation, base64, so a client can verify the statement it just
    /// received. With no registry to look the key up in, this is the only way it reaches anyone.
    pub key_attestation: String,
}

#[cfg(test)]
mod tests {
    use super::{MatchRequestBody, MatchResponseBody};

    /// Pins the field names both ends put on the wire. A round trip alone would not: renaming a
    /// field moves the serializer and the deserializer together and still passes.
    #[test]
    fn the_request_keeps_its_wire_names() {
        let body = MatchRequestBody {
            challenge_image_id: "3f2504e0".to_owned(),
            ciphertext: "c2VhbGVk".to_owned(),
        };
        let json = serde_json::json!({
            "challenge_image_id": "3f2504e0",
            "ciphertext": "c2VhbGVk",
        });

        assert_eq!(serde_json::to_value(&body).expect("should serialize"), json);
        assert_eq!(
            serde_json::from_value::<MatchRequestBody>(json).expect("should deserialize"),
            body
        );
    }

    #[test]
    fn the_response_keeps_its_wire_names() {
        let body = MatchResponseBody {
            response_ciphertext: "c2VhbGVk".to_owned(),
            key_attestation: "Y29zZQ==".to_owned(),
        };
        let json = serde_json::json!({
            "response_ciphertext": "c2VhbGVk",
            "key_attestation": "Y29zZQ==",
        });

        assert_eq!(serde_json::to_value(&body).expect("should serialize"), json);
        assert_eq!(
            serde_json::from_value::<MatchResponseBody>(json).expect("should deserialize"),
            body
        );
    }
}

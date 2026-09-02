use serde::{Deserialize, Serialize};

/// `POST /v1/matches` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchRequestBody {
    /// Object in the host's bucket holding the encrypted challenge image. Plaintext, so the
    /// host can start the fetch without opening anything.
    pub challenge_image_id: String,
    /// The sealed match request, base64.
    pub ciphertext: String,
}

/// `POST /v1/matches` response.
///
/// No cleartext outcome: whether a match held is itself a fact about the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchResponseBody {
    /// The sealed outcome, base64.
    pub response_ciphertext: String,
    /// The signing-key attestation, base64, so a client can verify the statement it received.
    pub key_attestation: String,
}

#[cfg(test)]
mod tests {
    use super::{MatchRequestBody, MatchResponseBody};

    /// Pins the wire names. A round trip alone would not: a rename moves both ends together.
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

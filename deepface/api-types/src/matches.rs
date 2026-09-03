use serde::{Deserialize, Serialize};

/// `POST /v1/matches` request.
///
/// One field. Every input the enclave needs is sealed inside it, so the host has nothing to look
/// up, nothing to fetch, and no plaintext field it could be induced to act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchRequestBody {
    /// The sealed match request, base64.
    pub ciphertext: String,
}

/// `POST /v1/matches` response.
///
/// No cleartext outcome: whether a match held is itself a fact about the request. The
/// signing-key attestation travels sealed inside, beside the statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchResponseBody {
    /// The sealed outcome, base64.
    pub response_ciphertext: String,
}

#[cfg(test)]
mod tests {
    use super::{MatchRequestBody, MatchResponseBody};

    /// Pins the wire names. A round trip alone would not: a rename moves both ends together.
    #[test]
    fn the_request_keeps_its_wire_names() {
        let body = MatchRequestBody {
            ciphertext: "c2VhbGVk".to_owned(),
        };
        let json = serde_json::json!({ "ciphertext": "c2VhbGVk" });

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
        };
        let json = serde_json::json!({ "response_ciphertext": "c2VhbGVk" });

        assert_eq!(serde_json::to_value(&body).expect("should serialize"), json);
        assert_eq!(
            serde_json::from_value::<MatchResponseBody>(json).expect("should deserialize"),
            body
        );
    }
}

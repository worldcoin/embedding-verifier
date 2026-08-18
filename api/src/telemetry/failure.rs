//! Failure classification shared by logs and metrics.

use crate::enclave::EnclaveClientError;

/// Coarse cause of a failed operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// The caller sent something we could not accept.
    Client,
    /// A dependency was unreachable or misbehaved.
    Dependency,
    /// A dependency did not answer within its deadline.
    Timeout,
    /// The enclave was reachable but refused to serve.
    Enclave,
    /// We ran out of capacity and shed the request.
    Saturation,
    /// A defect on our side.
    Internal,
}

impl FailureClass {
    /// Stable name, used as a metric tag value and a log field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Dependency => "dependency",
            Self::Timeout => "timeout",
            Self::Enclave => "enclave",
            Self::Saturation => "saturation",
            Self::Internal => "internal",
        }
    }

    /// Whether the fault is on our side. Drives log level: ours is `error`, theirs `warn`.
    #[must_use]
    pub const fn is_our_fault(self) -> bool {
        matches!(self, Self::Dependency | Self::Enclave | Self::Internal)
    }
}

impl From<&EnclaveClientError> for FailureClass {
    fn from(error: &EnclaveClientError) -> Self {
        use enclave_types::EnclaveError;

        match error {
            EnclaveClientError::Timeout => Self::Timeout,
            EnclaveClientError::Transport(_) => Self::Dependency,
            EnclaveClientError::Operation(operation) => match operation {
                EnclaveError::DecryptFailed
                | EnclaveError::MalformedMatchPayload
                | EnclaveError::InvalidHashesJson
                | EnclaveError::ThumbnailHashMismatch
                | EnclaveError::MatchBelowThreshold => Self::Client,
                EnclaveError::NotReady
                | EnclaveError::SecureModuleNotInitialized
                | EnclaveError::AttestationFailed => Self::Enclave,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use enclave_types::EnclaveError;

    use super::FailureClass;
    use crate::enclave::EnclaveClientError;

    #[test]
    fn callers_faults_are_not_ours() {
        let client =
            FailureClass::from(&EnclaveClientError::Operation(EnclaveError::DecryptFailed));
        let ours = FailureClass::from(&EnclaveClientError::Operation(EnclaveError::NotReady));

        assert_eq!(client, FailureClass::Client);
        assert!(!client.is_our_fault());
        assert!(ours.is_our_fault());
    }

    #[test]
    fn timeouts_are_distinct_from_transport_failures() {
        assert_eq!(
            FailureClass::from(&EnclaveClientError::Timeout),
            FailureClass::Timeout
        );
        assert_eq!(
            FailureClass::from(&EnclaveClientError::Transport(String::new())),
            FailureClass::Dependency
        );
    }
}

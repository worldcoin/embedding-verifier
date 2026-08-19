use pontifex::Request;
use serde::{Deserialize, Serialize};

use crate::EnclaveError;

/// Requests the current health of the enclave.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct HealthRequest;

impl Request for HealthRequest {
    const ROUTE_ID: &'static str = "/v1/health";
    type Response = Result<(), EnclaveError>;
}

#[cfg(test)]
mod tests {
    use pontifex::Request;

    use super::HealthRequest;

    #[test]
    fn health_route_id_is_versioned_and_stable() {
        assert_eq!(HealthRequest::ROUTE_ID, "/v1/health");
    }
}

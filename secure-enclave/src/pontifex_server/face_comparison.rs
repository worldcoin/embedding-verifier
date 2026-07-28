use std::sync::Arc;

use enclave_types::{CompareFacesRequest, CompareFacesResponse, EnclaveError};

use crate::{face_engine, state::EnclaveState};

pub async fn handler(
    _: Arc<EnclaveState>,
    request: CompareFacesRequest,
) -> Result<CompareFacesResponse, EnclaveError> {
    face_engine::compare(request.reference_image, request.probe_image)
}

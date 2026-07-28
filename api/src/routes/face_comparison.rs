use axum::{Json, extract::State, http::StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use enclave_types::{CompareFacesRequest, EnclaveError};
use serde::{Deserialize, Serialize};

use crate::{enclave::EnclaveClientError, types::AppState};

const MAX_IMAGE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompareFacesBody {
    reference_image: String,
    probe_image: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompareFacesBodyResponse {
    similarity: f32,
    matches: bool,
}

pub async fn handler(
    State(state): State<AppState>,
    Json(body): Json<CompareFacesBody>,
) -> Result<Json<CompareFacesBodyResponse>, StatusCode> {
    let reference_image = STANDARD
        .decode(body.reference_image)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let probe_image = STANDARD
        .decode(body.probe_image)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    if reference_image.is_empty()
        || probe_image.is_empty()
        || reference_image.len() > MAX_IMAGE_BYTES
        || probe_image.len() > MAX_IMAGE_BYTES
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let response = state
        .enclave_client()
        .compare_faces(CompareFacesRequest {
            reference_image,
            probe_image,
        })
        .await
        .map_err(|error| {
            let status = match error {
                EnclaveClientError::Operation(
                    EnclaveError::InvalidImage | EnclaveError::EmbeddingGenerationFailed,
                ) => StatusCode::UNPROCESSABLE_ENTITY,
                EnclaveClientError::Operation(EnclaveError::EmbeddingComparisonFailed) => {
                    StatusCode::INTERNAL_SERVER_ERROR
                }
                EnclaveClientError::Operation(_)
                | EnclaveClientError::Timeout
                | EnclaveClientError::Transport(_) => StatusCode::SERVICE_UNAVAILABLE,
            };
            tracing::warn!(?error, %status, "face comparison failed");
            status
        })?;

    Ok(Json(CompareFacesBodyResponse {
        similarity: response.similarity,
        matches: response.matches,
    }))
}

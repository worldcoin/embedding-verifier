use axum::{Json, extract::State, http::StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use deepface_api_types::{ExtractEmbeddingRequestBody, ExtractEmbeddingResponseBody};
use deepface_enclave_types as enclave;

use crate::AppState;
use crate::error::AppError;

/// Relays a sealed embedding extraction request to the enclave.
///
/// # Errors
///
/// Returns [`AppError`] if the ciphertext is malformed or the enclave rejects the request.
pub async fn handler(
    State(state): State<AppState>,
    Json(body): Json<ExtractEmbeddingRequestBody>,
) -> Result<(StatusCode, Json<ExtractEmbeddingResponseBody>), AppError> {
    let ciphertext = STANDARD.decode(body.ciphertext.trim()).map_err(|_| {
        AppError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The sealed embedding extraction request was not valid base64",
            false,
        )
    })?;

    tracing::info!(
        sealed_request_bytes = ciphertext.len(),
        "forwarding sealed embedding extraction request to enclave"
    );

    let response = state
        .enclave_client()
        .extract_embedding(enclave::ExtractEmbeddingRequest { body: ciphertext })
        .await
        .map_err(|error| AppError::enclave_embedding_extraction(&error))?;

    Ok((
        StatusCode::OK,
        Json(ExtractEmbeddingResponseBody {
            response_ciphertext: STANDARD.encode(response.ciphertext),
        }),
    ))
}

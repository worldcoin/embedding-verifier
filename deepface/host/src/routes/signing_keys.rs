use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderName, HeaderValue, header};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;

use crate::AppState;
use crate::error::AppError;
use crate::key_registry::{KeyStatus, RegistryEntry};

/// How long a client may reuse a lookup.
///
/// Not `immutable`, even though the `public_key` → attestation binding never changes: `status`
/// does, and a revocation has to reach verifiers. Clients that want the binding forever cache it
/// themselves.
const CACHE_CONTROL: &str = "public, max-age=60";

/// One `Signing Key`'s validity, and the document that attests it.
#[derive(Debug, Serialize)]
pub struct SigningKeyResponse {
    /// The key, canonical `0x` hex.
    public_key: String,
    /// The COSE attestation document, base64.
    attestation: String,
    /// The image measurement the document reports, `0x` hex.
    pcr0: String,
    /// When the key was attested, in seconds since the Unix epoch.
    valid_from: u64,
    /// When the enclave shut down, if it has.
    retired_at: Option<u64>,
    /// Validity state.
    status: KeyStatus,
}

impl From<RegistryEntry> for SigningKeyResponse {
    fn from(entry: RegistryEntry) -> Self {
        Self {
            public_key: entry.public_key.to_string(),
            attestation: STANDARD.encode(entry.attestation),
            pcr0: format!("0x{}", hex::encode(entry.pcr0)),
            valid_from: entry.valid_from,
            retired_at: entry.retired_at,
            status: entry.status,
        }
    }
}

/// Serves the registry entry for one signing key.
///
/// # Errors
///
/// Returns [`AppError`]: `400` if the path is not a signing key, `404` if this `Service` never
/// issued it, and `503`/`500` if the registry could not be read. A registry that cannot be read
/// is never reported as `404` — that answer is terminal for the caller.
pub async fn handler(
    State(state): State<AppState>,
    Path(public_key): Path<String>,
) -> Result<([(HeaderName, HeaderValue); 1], Json<SigningKeyResponse>), AppError> {
    let public_key = public_key
        .parse()
        .map_err(|error| AppError::invalid_signing_public_key(&error))?;

    let entry = state
        .key_registry()
        .get(public_key)
        .await
        .map_err(|error| AppError::key_registry(&error))?
        .ok_or_else(AppError::unknown_signing_key)?;

    Ok((
        [(
            header::CACHE_CONTROL,
            HeaderValue::from_static(CACHE_CONTROL),
        )],
        Json(SigningKeyResponse::from(entry)),
    ))
}

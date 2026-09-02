//! The HTTP contract between the `DeepFace` client and its host.
//!
//! One definition per message, shared by both ends. Declaring these twice — once to serialize
//! and once to deserialize — lets a field rename compile on both sides and fail at runtime, so
//! the point of this crate is that there is nowhere for the two to drift apart.
//!
//! Everything here is a wire shape and nothing more: no behaviour, and no opinion about what
//! the fields mean. The bodies are opaque even to the host, which relays ciphertext it holds no
//! key for. The sealed payload inside them is `deepface-protocol`; the vsock contract the host
//! speaks to the enclave is `deepface-enclave-types`.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

mod assignment;
mod error;
mod matches;

pub use assignment::EnclaveAssignmentResponse;
pub use error::{ApiError, ApiErrorResponse};
pub use matches::{MatchRequestBody, MatchResponseBody};

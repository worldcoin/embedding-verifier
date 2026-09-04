//! The crate's error type.

/// Why a sealed match payload could not be encoded or decoded. Local only, never travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The bytes were not the CBOR framing this crate writes.
    Malformed,
    /// CBOR encoding failed.
    Encoding,
    /// An encoded match result exceeded its fixed sealed-response envelope.
    ResponseTooLarge,
    /// Match inputs declared a channel version this build does not implement.
    UnsupportedChannelVersion,
}

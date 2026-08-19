//! Cryptography shared by the enclave and the client.
//!
//! Everything here sits on the **client↔enclave** side of the trust boundary: the enclave
//! produces it, the client consumes it, and the host only ever relays bytes it holds no key for.
//! That is why this is its own crate rather than part of `enclave-types`, which describes the
//! vsock protocol the host *does* participate in and legitimately reads. The separation is
//! checkable: `cargo tree -p host` has no edge to `hpke`, `aes-gcm`, or `hkdf`.
//!
//! Anything added here inherits that boundary. If the host ever needs it, it belongs in
//! `enclave-types` instead.
//!
//! - [`sealed_channel`] — the HPKE sealed channel carrying match inputs and outcomes.
//!
//! Match statement signing lands beside it next.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

pub mod sealed_channel;

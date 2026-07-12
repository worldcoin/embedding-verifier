# Embedding Verifier

Rust workspace for the embedding verifier API and secure enclave.

## Structure

```text
embedding-verifier/
├── api/              # Axum HTTP API
└── secure-enclave/   # Secure enclave process
```

## Development

```bash
# Run formatting and lint checks
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --

# Build and test the workspace
cargo build
cargo test --all

# Run the API on http://localhost:8000
RUST_LOG=info cargo run --bin api
curl http://localhost:8000/health

# Run the secure enclave placeholder
RUST_LOG=info cargo run --bin secure-enclave
```

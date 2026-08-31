# syntax=docker/dockerfile:1
# Enclave workload image, converted to an EIF by scripts/build-eif.sh --workload di.
#
# This directory is its own cargo workspace, so PCR0 depends on
# di/enclave/{Cargo.toml,Cargo.lock} and the path crates they name — not on the host-side
# workspace, and not on the deepface enclave. Nothing in this graph comes from a private
# repository, so unlike deepface/enclave/Dockerfile this build needs no GITHUB_TOKEN.

FROM rust:1.97.0-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cargo build --release --locked \
      --manifest-path di/enclave/Cargo.toml \
      --bin di-enclave

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/di/enclave/target/release/di-enclave /usr/local/bin/di-enclave

ENV RUST_LOG=info

ENTRYPOINT ["/usr/local/bin/di-enclave"]

# syntax=docker/dockerfile:1
# Enclave workload image, converted to an EIF by scripts/build-eif.sh --workload di.
#
# Base images are tag-pinned and the build is --locked. Before a PRODUCTION
# deploy, pin base images by digest + apt to a snapshot.debian.org timestamp so
# PCRs are reproducible, then register the real PCRs (dev runs --debug-mode,
# which zeroes PCRs and skips attestation).
#
# Unlike deepface/enclave/Dockerfile this needs no build secrets: di-enclave
# depends only on di-types, tracing and tracing-subscriber, so there is no
# private git dependency to authenticate and no model bundle to download. Both
# come back when the iris pipeline lands — models are injected at runtime per
# the spec, so HUGGING_FACE_TOKEN should not return here.

FROM rust:1.97.0-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cargo build --release --locked --package di-enclave --bin di-enclave

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/di-enclave /usr/local/bin/di-enclave

ENV RUST_LOG=info

ENTRYPOINT ["/usr/local/bin/di-enclave"]

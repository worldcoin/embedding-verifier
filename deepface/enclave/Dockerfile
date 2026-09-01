# syntax=docker/dockerfile:1
# Enclave workload image, converted to an EIF by scripts/build-eif.sh.
#
# This directory is its own cargo workspace: PCR0 depends on
# deepface/enclave/{Cargo.toml,Cargo.lock} and the path crates they name, and on nothing the
# host-side workspace resolves. The build is --locked so a stale lockfile fails here.
#
# Base images are tag-pinned. Before a PRODUCTION deploy, pin base images by digest + apt to a
# snapshot.debian.org timestamp so PCRs are reproducible, then register the real PCRs (dev runs
# --debug-mode, which zeroes PCRs and skips attestation).

FROM rust:1.97.0-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        clang \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN --mount=type=secret,id=GITHUB_TOKEN,required=true \
    GITHUB_TOKEN="$(cat /run/secrets/GITHUB_TOKEN)" && \
    git config --global \
      url."https://x-access-token:${GITHUB_TOKEN}@github.com/worldcoin/biometric-engines".insteadOf \
      "https://github.com/worldcoin/biometric-engines" && \
    CARGO_NET_GIT_FETCH_WITH_CLI=true \
      cargo build --release --locked \
        --manifest-path deepface/enclave/Cargo.toml \
        --bin deepface-enclave && \
    git config --global --unset-all \
      url."https://x-access-token:${GITHUB_TOKEN}@github.com/worldcoin/biometric-engines".insteadOf

FROM python:3.12.11-slim-bookworm AS model-downloader

WORKDIR /build
COPY scripts/download-face-models.py scripts/download-face-models.py

RUN python3 -m pip install --no-cache-dir huggingface-hub==0.34.4

RUN --mount=type=secret,id=HUGGING_FACE_TOKEN,required=true \
    HUGGING_FACE_TOKEN="$(cat /run/secrets/HUGGING_FACE_TOKEN)" \
      python3 scripts/download-face-models.py --output /models

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/deepface/enclave/target/release/deepface-enclave /usr/local/bin/deepface-enclave
COPY --from=model-downloader /models /models

ENV RUST_LOG=info

ENTRYPOINT ["/usr/local/bin/deepface-enclave"]

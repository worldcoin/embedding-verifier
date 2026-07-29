# syntax=docker/dockerfile:1
# Enclave workload image, converted to an EIF by scripts/build-eif.sh.
#
# Base images are tag-pinned and the build is --locked. Before a PRODUCTION
# deploy, pin base images by digest + apt to a snapshot.debian.org timestamp so
# PCRs are reproducible, then register the real PCRs (dev runs --debug-mode,
# which zeroes PCRs and skips attestation).

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
      url."https://${GITHUB_TOKEN}:x-oauth-basic@github.com/".insteadOf \
      "https://github.com/" && \
    CARGO_NET_GIT_FETCH_WITH_CLI=true \
      cargo build --release --locked --package secure-enclave --bin secure-enclave && \
    git config --global --unset-all \
      url."https://${GITHUB_TOKEN}:x-oauth-basic@github.com/".insteadOf

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/secure-enclave /usr/local/bin/secure-enclave
COPY --from=builder /src/models/face_embedding_generator.onnx /models/face_embedding_generator.onnx
COPY --from=builder /src/models/rgbnet.onnx /models/rgbnet.onnx

ENV RUST_LOG=info

ENTRYPOINT ["/usr/local/bin/secure-enclave"]

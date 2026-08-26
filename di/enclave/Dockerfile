# syntax=docker/dockerfile:1
# Enclave workload image, converted to an EIF by scripts/build-eif.sh --workload di.
#
# Base images are tag-pinned and the build is --locked. Before a PRODUCTION
# deploy, pin base images by digest + apt to a snapshot.debian.org timestamp so
# PCRs are reproducible, then register the real PCRs (dev runs --debug-mode,
# which zeroes PCRs and skips attestation).
#
# GITHUB_TOKEN despite di-enclave using nothing private: cargo resolves the whole
# workspace, so face-engine is fetched whichever --package is selected.

FROM rust:1.97.0-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN --mount=type=secret,id=GITHUB_TOKEN,required=true \
    GITHUB_TOKEN="$(cat /run/secrets/GITHUB_TOKEN)" && \
    git config --global \
      url."https://x-access-token:${GITHUB_TOKEN}@github.com/worldcoin/biometric-engines".insteadOf \
      "https://github.com/worldcoin/biometric-engines" && \
    CARGO_NET_GIT_FETCH_WITH_CLI=true \
      cargo build --release --locked --package di-enclave --bin di-enclave && \
    git config --global --unset-all \
      url."https://x-access-token:${GITHUB_TOKEN}@github.com/worldcoin/biometric-engines".insteadOf

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/di-enclave /usr/local/bin/di-enclave

ENV RUST_LOG=info

ENTRYPOINT ["/usr/local/bin/di-enclave"]

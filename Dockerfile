# syntax=docker/dockerfile:1

# Builds the host-side `api` service as a statically-linked musl binary and
# packages it in a `scratch` image.

FROM ghcr.io/rust-cross/rust-musl-cross:x86_64-musl AS chef
USER root
WORKDIR /app

COPY rust-toolchain.toml .
RUN rustup show \
 && rustup target add x86_64-unknown-linux-musl
RUN cargo install cargo-chef --locked

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json

RUN --mount=type=secret,id=GITHUB_TOKEN,required=true \
    GITHUB_TOKEN="$(cat /run/secrets/GITHUB_TOKEN)" && \
    git config --global \
      url."https://x-access-token:${GITHUB_TOKEN}@github.com/worldcoin/biometric-engines".insteadOf \
      "https://github.com/worldcoin/biometric-engines" && \
    CARGO_NET_GIT_FETCH_WITH_CLI=true cargo chef cook --release --locked \
      --target x86_64-unknown-linux-musl \
      --recipe-path recipe.json \
      --package api && \
    git config --global --unset-all \
      url."https://x-access-token:${GITHUB_TOKEN}@github.com/worldcoin/biometric-engines".insteadOf
COPY . .
RUN --mount=type=secret,id=GITHUB_TOKEN,required=true \
    GITHUB_TOKEN="$(cat /run/secrets/GITHUB_TOKEN)" && \
    git config --global \
      url."https://x-access-token:${GITHUB_TOKEN}@github.com/worldcoin/biometric-engines".insteadOf \
      "https://github.com/worldcoin/biometric-engines" && \
    CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release --locked \
      --target x86_64-unknown-linux-musl \
      --package api \
 && mv target/x86_64-unknown-linux-musl/release/api /app/api-bin \
 && git config --global --unset-all \
      url."https://x-access-token:${GITHUB_TOKEN}@github.com/worldcoin/biometric-engines".insteadOf

FROM scratch AS runtime
WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/api-bin /usr/local/bin/api

# Run unprivileged (nonroot UID). The static binary needs no shell or libc.
USER 65532

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/api"]

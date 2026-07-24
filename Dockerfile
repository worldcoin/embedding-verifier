# syntax=docker/dockerfile:1

# Builds the host-side `api` service as a statically-linked musl binary and
# packages it in a `scratch` image. Mirrors the world-id-protocol build pattern
# (rust-musl-cross base + cargo-chef dependency caching).

####################################################################################################
## Base / dependency planner
####################################################################################################
FROM ghcr.io/rust-cross/rust-musl-cross:x86_64-musl AS chef
USER root
WORKDIR /app

# Install the toolchain pinned by rust-toolchain.toml, then the musl target.
COPY rust-toolchain.toml .
RUN rustup show \
 && rustup target add x86_64-unknown-linux-musl
RUN cargo install cargo-chef --locked

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

####################################################################################################
## Builder
####################################################################################################
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Cache dependency compilation for the `api` package — this is the heavy layer.
RUN cargo chef cook --release --locked \
      --target x86_64-unknown-linux-musl \
      --recipe-path recipe.json \
      --package api
COPY . .
RUN cargo build --release --locked \
      --target x86_64-unknown-linux-musl \
      --package api \
 && mv target/x86_64-unknown-linux-musl/release/api /app/api-bin

####################################################################################################
## Runtime
####################################################################################################
FROM scratch AS runtime
WORKDIR /app

# CA roots so future outbound TLS (if added) works; harmless otherwise.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/api-bin /usr/local/bin/api

# Run unprivileged (nonroot UID). The static binary needs no shell or libc.
USER 65532

# API binds 0.0.0.0:$PORT (default 8000, see api/src/server.rs).
EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/api"]

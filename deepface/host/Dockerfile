# syntax=docker/dockerfile:1

# Builds the `deepface-host` service as a statically-linked musl binary and packages it
# in a `scratch` image. Built with the repository root as the context.

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

RUN cargo chef cook --release --locked \
      --target x86_64-unknown-linux-musl \
      --recipe-path recipe.json \
      --package deepface-host
COPY . .
RUN cargo build --release --locked \
      --target x86_64-unknown-linux-musl \
      --package deepface-host \
 && mv target/x86_64-unknown-linux-musl/release/deepface-host /app/host-bin

FROM scratch AS runtime
WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/host-bin /usr/local/bin/deepface-host

# Run unprivileged (nonroot UID). The static binary needs no shell or libc.
USER 65532

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/deepface-host"]

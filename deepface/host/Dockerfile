# syntax=docker/dockerfile:1

FROM ghcr.io/rust-cross/rust-musl-cross:x86_64-musl AS builder
USER root
WORKDIR /app

COPY . .
RUN rustup show \
 && rustup target add x86_64-unknown-linux-musl
RUN --mount=type=secret,id=github_token \
    git config --global credential."https://github.com".helper \
      "!f() { echo username=x-access-token; echo password=$(cat /run/secrets/github_token); }; f" \
 && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release --locked \
      --target x86_64-unknown-linux-musl \
      --package deepface-host \
 && rm -f /root/.gitconfig \
 && mv target/x86_64-unknown-linux-musl/release/deepface-host /app/host-bin

FROM scratch AS runtime
WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/host-bin /usr/local/bin/deepface-host

USER 65532

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/deepface-host"]

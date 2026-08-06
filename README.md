# Embedding Verifier

Rust workspace for the embedding verifier API and secure enclave.

## Structure

```text
embedding-verifier/
├── api/              # Axum HTTP API
└── secure-enclave/   # Secure enclave process
```

## Secure channel

Matches run over an end-to-end HPKE channel (RFC 9180) between the client and the enclave.
The API host relays ciphertext in both directions and holds no key that would let it read
or alter either half. The ciphersuite is fixed — DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256
+ ChaCha20-Poly1305 — and pinned at the type level in `secure-enclave/src/state.rs`.

### 1. Fetch and verify the transit key

`GET /v1/enclave/transit-key` returns `{"attestation": "<base64 COSE document>"}`, an NSM
attestation whose `public_key` field is the enclave's boot-scoped X25519 transit key. The
document carries **no client nonce**, deliberately: it claims "this key lives in an enclave
running image X", which is time-invariant, so replaying it states something true. The age
bound comes from the Nitro leaf certificate instead, which lives three hours.

Verification is the client's job and is load-bearing. It must check, at minimum:

- the COSE signature, and the certificate chain up to the AWS Nitro root
- certificate validity, including `notAfter` — this is the entire freshness bound
- the expected `PCR0`, `PCR1`, and `PCR2` (plus `PCR8` if the EIF is signed)
- that those PCRs are **not** all zero, which means the enclave was booted with
  `--debug-mode`. Development deployments run in exactly that mode, so a client that skips
  this check would accept a debug enclave in production

### 2. Send a match request

Run `SetupBaseS` against the transit key with
`info = "embedding-verifier/match" || version || transit_pk` (see
`enclave_types::channel_info`), seal the CBOR-framed match inputs with an empty AAD, and
`POST /v1/matches` with `Content-Type: application/octet-stream` and a body of

```text
enc (32 bytes) || ciphertext
```

### 3. Open the response

The response body is raw ciphertext. Export the response key and nonce from the *same*
sender context (RFC 9180 §9.8) using the contexts `"response key"` (32 bytes) and
`"response nonce"` (12 bytes), then open it with ChaCha20-Poly1305, passing a one-byte AAD
of `0x01` on `200` and `0x02` on `422`. The plaintext is a CBOR
`Result<MatchStatement, RejectReason>` and is the authoritative outcome — the status code
is a hint, and a host that rewrites it only breaks the AAD.

Only the holder of `transit_sk` can derive that exporter secret, so opening the response
also authenticates its origin. Statuses the host can produce on its own — `400`, `503`,
`504` — carry no body and are not authenticated; at worst a hostile host denies service.

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

## Nitro-enabled development host

Use an Amazon Linux 2023 EC2 instance type that supports Nitro Enclaves and launch it with
Nitro Enclaves enabled. Limit inbound SSH access to your current public IP.

On the instance, install the development tools and Nitro Enclaves runtime:

```bash
sudo dnf install -y \
  git wget jq tmux tree unzip tar gzip \
  gcc gcc-c++ make cmake clang pkgconf-pkg-config openssl-devel \
  bubblewrap docker aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel

sudo usermod -aG ne "$USER"
sudo usermod -aG docker "$USER"
sudo systemctl enable --now nitro-enclaves-allocator.service
sudo systemctl enable --now docker
```

These commands follow the [AWS Nitro Enclaves setup for Amazon Linux 2023](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html).

The allocator defaults to 2 vCPUs and 512 MiB. Adjust
`/etc/nitro_enclaves/allocator.yaml` before starting the service when the enclave needs more.
Log out and reconnect after changing group membership, then verify the host:

```bash
nitro-cli --version
nitro-cli describe-enclaves
docker version
```

Install Rust and the components used by this workspace:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup component add rustfmt clippy
cargo test --all
```

For private repository access, install and authenticate the GitHub CLI using its
[official RPM instructions](https://github.com/cli/cli/blob/trunk/docs/install_linux.md#dnf4).

Optionally install Codex for development on the remote host:

```bash
curl -fsSL https://chatgpt.com/codex/install.sh | sh
exec "$SHELL" -l
codex login --device-auth
codex doctor
```

To use the Codex desktop app, add a concrete host alias to your local `~/.ssh/config`, confirm
`ssh <alias>` works, then select the host and repository path under **Settings > Connections**.
See the [Codex remote connection guide](https://learn.chatgpt.com/docs/remote-connections#connect-to-an-ssh-host).

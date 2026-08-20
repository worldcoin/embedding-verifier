# Embedding Verifier

Rust workspace for the embedding verifier host and secure enclave.

## Structure

One directory per workspace member, named after the crate it holds.

```text
embedding-verifier/
├── host/              # Axum HTTP API — the untrusted side of the boundary
├── enclave/           # Nitro enclave workload — the trusted side
├── enclave-types/     # Wire contract carried over vsock between the two
├── attested-channel/  # Client↔enclave channel and the attestation it rests on; destined for pontifex
├── client/            # Attestation-verifying client
└── e2e/               # End-to-end harness driving host and enclave together
```

## Development

```bash
# Run formatting and lint checks
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --

# Build and test the workspace
cargo build
cargo test --all

# Run the host on http://localhost:8000
# ENCLAVE_CID and ENCLAVE_PORT are required; the process panics without them.
RUST_LOG=info ENCLAVE_CID=16 ENCLAVE_PORT=1000 cargo run --bin host
curl http://localhost:8000/health

# Run the secure enclave placeholder
RUST_LOG=info cargo run --bin enclave
```

## Enclave assignment

`POST /v1/enclave-assignment` returns the enclave's encryption-key attestation and nothing
else:

```json
{ "attestation": "<base64 COSE_Sign1>" }
```

The enclave's identity (`module_id`) and expiry (the leaf certificate's `notAfter`) are read
from the document *after* verifying it, never from fields the untrusted host could set.

`client` verifies the document — the COSE signature, the certificate chain up to the
pinned AWS Nitro root, and the expected measurements. It is configured by a JSON file, in the
shape `world-id-protocol` uses for an authenticator:

```json
{
  "host_url": "http://localhost:8000",
  "allowed_pcr_configs": [
    [{ "index": 0, "value": "<PCR0 hex from scripts/build-eif.sh>" }]
  ],
  "max_attestation_age_millis": 3600000,
  "allow_debug_measurements": false
}
```

Only `host_url` and `allowed_pcr_configs` are required; the rest have defaults. A
configuration that pins no measurements is rejected — with nothing pinned, verification only
proves a document came from *some* enclave. A `--debug-mode` enclave reports all-zero PCRs and
its memory is readable from the parent instance, so it is rejected unless
`allow_debug_measurements` is set.

`e2e` reads that file from `VERIFIER_CONFIG` and fetches its encryption key
through the host, exercising the assignment route and the client together:

```bash
VERIFIER_CONFIG=./client.json cargo run --bin e2e -- <credential> <live> <challenge>
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

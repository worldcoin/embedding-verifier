# Embedding Verifier

Rust workspace for the embedding verifier API and secure enclave.

## Structure

```text
embedding-verifier/
├── api/              # Axum HTTP API
└── secure-enclave/   # Secure enclave process
```

## Development

```bash
# Run formatting and lint checks
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --

# Build and test the workspace
cargo build
cargo test --all

# Run the API on http://localhost:8000
RUST_LOG=info ENCLAVE_CID=16 ENCLAVE_PORT=1000 cargo run --bin api
curl http://localhost:8000/healthz   # liveness: the process
curl http://localhost:8000/readyz    # readiness: names any unmet condition

# Run the secure enclave placeholder
RUST_LOG=info cargo run --bin secure-enclave
```

## Configuration

Resolved once at startup; the process refuses to boot listing every problem it found.

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `ENCLAVE_CID` | yes | — | vsock CID of the local enclave |
| `ENCLAVE_PORT` | yes | — | Pontifex port the enclave serves on |
| `APP_ENV` | no | `development` | `production`, `staging`, or `development` |
| `PORT` | no | `8000` | HTTP listener port |
| `SHUTDOWN_DRAIN_SECONDS` | no | `5` | Time spent unready but still serving after SIGTERM. Must exceed load-balancer deregistration |
| `DD_AGENT_HOST` | no | — | DogStatsD host. Unset disables metrics |
| `DD_DOGSTATSD_PORT` | no | `8125` | DogStatsD port |

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

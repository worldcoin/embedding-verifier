# Embedding Verifier

Rust workspace for the embedding verifier API and secure enclave.

## Structure

```text
embedding-verifier/
├── api/                    # Axum HTTP API
├── secure-enclave/         # Secure enclave process
└── shared/enclave-types/   # Host-to-enclave wire contracts
```

## Development

```bash
# Check the workspace
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features --
cargo test --locked --all
cargo build --locked --release
cargo deny check

# Run the API on http://localhost:8000
RUST_LOG=info cargo run --bin api
curl http://localhost:8000/health
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
cargo test --locked --all
```

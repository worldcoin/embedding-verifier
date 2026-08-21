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
├── deepface-protocol/ # Match inputs and outputs; travels sealed, the host links none of it. Will likely move to `world-id-protocol`.
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

Documents are cached **inside the enclave** for 10 minutes (`MAX_CACHED_AGE`); the first read after
that re-attests before answering, so an outdated document is never served and all but one request
per interval skips the NSM entirely. The cache is boot-scoped, so a restart takes it along and there
is nothing for the host to invalidate.

A burst arriving on an expired document costs one attestation, not one per caller: the lock spans
the check and the re-attestation.

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

## Matches

`POST /v1/matches` compares a credential image against a live frame and the RP's challenge
frame. The host relays but cannot read either input:

```json
{ "challenge_image_url": "https://…", "ciphertext": "<base64 enc || ciphertext>" }
```

`ciphertext` is the match inputs sealed to the enclave's attested encryption key — both
images, `hashes.json`, and the AES-256-GCM key and IV for the challenge image. The challenge
image itself never travels: the RP uploads it encrypted, and the host fetches that blob from
`challenge_image_url` holding no key for it. A substituted URL or swapped object therefore
fails inside the enclave rather than changing the result.

```json
{ "response_ciphertext": "<base64 nonce || ciphertext>", "key_attestation": "<base64 COSE_Sign1>" }
```

The sealed response carries either a `COSE_Sign1` match statement or the reason no statement was
issued; `key_attestation` is the signing key's attestation, so a client can verify the statement it
just received. Only the requester can open it — a second channel to the same enclave key cannot.

The host learns only that the enclave answered. Once a request has been opened there is a sealed
channel to reply on, so everything the enclave discovers from that point — a malformed payload, an
unusable `hashes.json`, an image refused on quality grounds, a below-threshold score, a challenge
blob that would not decrypt — travels inside `response_ciphertext`. None of it reaches the status
code.

| Status | Meaning |
| --- | --- |
| `200` | The enclave answered; the sealed payload holds the outcome |
| `409` `reassign_required` | The request did not open, so there was no channel to reply on; re-assign and re-seal, once |
| `400` `invalid_challenge_url` | The URL was rejected before any request was made |
| `502` `challenge_fetch_failed` | The challenge image could not be fetched |
| `500` `internal_error` | Enclave fault |

`409` is the only input failure with a status of its own, because with no channel open there is
nothing to seal a reply into. Everything else the host might want — how often matches fail, how often
the RP's objects are stale — has to come from enclave-side metrics rather than from status codes.

> **No SSRF destination control.** `challenge_image_url` is only constrained in shape — HTTPS,
> a domain rather than an IP literal, no credentials, no redirects, a 5s timeout and a 4 MiB
> cap. Nothing pins *where* a fetch may go, so this endpoint must not take untrusted callers
> as-is. See `TODO(SSRF)` in `host/src/challenge_fetch.rs`.

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

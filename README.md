# Embedding Verifier

Rust workspaces for the embedding verifier host and secure enclave.

## Structure

Two workloads over the same host/enclave shape — the `DeepFace` verifier and the
`DeepIdentifier` migration. Each owns a top-level directory; what both would duplicate
lives in `shared/`. Crate names compose from the path: `deepface/host` is `deepface-host`.

```text
embedding-verifier/
├── Cargo.toml             # Host-side workspace  -> Cargo.lock
├── shared/
│   └── attested-channel/  # Client↔enclave channel and the attestation it rests on; destined for pontifex
├── deepface/
│   ├── host/              # Axum HTTP API — the untrusted side of the boundary
│   ├── enclave/           # Nitro enclave workload — the trusted side. Own workspace -> own Cargo.lock
│   ├── api-types/         # Client↔host HTTP contract; stops at the host, so no enclave links it
│   ├── enclave-types/     # Host↔enclave vsock contract: health, errors, key attestation, the match exchange
│   ├── protocol/          # Match inputs and outputs; travels sealed, the host links none of it. Will likely move to `world-id-protocol`.
│   ├── client/            # Attestation-verifying client
│   └── e2e/               # End-to-end harness driving host and enclave together
└── di/                    # Skeleton — dirs and crates only, no behaviour yet
    ├── host/
    └── enclave/           # Own workspace -> own Cargo.lock
```

One crate per boundary, in the graphs that boundary reaches. Nothing is shared between
`deepface/` and `di/`, because a shared crate means a `deepface` edit rotates `di`'s PCR0.

`di-host` and `di-enclave` log and exit non-zero — a skeleton that idled would read as healthy. See
[Spec: DeepIdentifier Migration TEE Setup v1](https://app.notion.com/p/worldcoin/Spec-DeepIdentifier-Migration-TEE-Setup-v1-3c08614bdf8c8014b7ddf50f3cac4e4b)
for what goes in them.

### Three workspaces, three lockfiles

Each enclave is its own cargo workspace. One lockfile for the whole repository meant a
`deepface-host` dependency bump re-resolved the enclave graph and moved PCR0, which clients
pin. Now an EIF's inputs are its own `Cargo.toml`, the `Cargo.lock` beside it, and the path
crates they name.

`attested-channel`, `deepface-protocol` and `deepface-enclave-types` are in both an enclave
graph and the host-side one. They are members of the root workspace but inherit nothing from it
— not `[workspace.dependencies]`, not `[workspace.package]` — so the root manifest cannot reach
an enclave graph either. Treat them as standalone crates: write the version, and the `edition`,
in their own manifest. `deepface-api-types` is host-side only and inherits normally.

`nix/enclave-binaries.nix` lists the crates each EIF build sees. A new path dependency has to be
added there or the build fails.

Package metadata matters as much as the dependency versions here. An inherited `edition` would
change how an enclave compiles when the root workspace moved, and bumping the root
`[workspace.package].version` would leave both enclave lockfiles stale against `--locked`.

`face-engine` now lives only in `deepface/enclave`, so it is the one build that needs a token
for `worldcoin/biometric-engines`. CI runs the other lanes without one, which is what keeps
that true.

## Development

Every command takes a `--manifest-path`, because there are three workspaces:

```bash
# From the repository root — cargo-deny reads deny.toml from the working directory.
for ws in . deepface/enclave di/enclave; do
  cargo fmt    --manifest-path "$ws/Cargo.toml" --all -- --check
  cargo clippy --manifest-path "$ws/Cargo.toml" --all-targets --all-features --
  cargo test   --manifest-path "$ws/Cargo.toml" --all
  cargo deny   --manifest-path "$ws/Cargo.toml" --all-features check
done
```

```bash
# Run the host on http://localhost:8000
# ENCLAVE_CID, ENCLAVE_PORT and CHALLENGE_IMAGE_BASE_URL are required; the process panics
# without them. The host pins no measurements of its own -- it is the untrusted side, and it is
# the client that pins PCR0.
RUST_LOG=info ENCLAVE_CID=16 ENCLAVE_PORT=1000 \
  CHALLENGE_IMAGE_BASE_URL=https://bucket.example.com/challenges/ \
  cargo run --bin deepface-host
curl http://localhost:8000/health

# Run the secure enclave placeholder
RUST_LOG=info cargo run --manifest-path deepface/enclave/Cargo.toml --bin deepface-enclave
```

## Building images

Each workload has a host image and a reproducible OCI enclave image. Nix builds the OCI
image instead of the old workload Dockerfile. It then loads that immutable image into Docker
and invokes a Nix-packaged AWS nitro-cli v1.4.2, preserving the pre-#38 LinuxKit and EIF
conversion path. `build-docker.yml` only builds and publishes hosts.

```bash
# Reproducible OCI image -> AWS nitro-cli -> EIF + PCRs.
# Needs Linux x86_64 and Docker; Nitro hardware is only needed to run.
scripts/build-eif.sh --workload deepface   # -> target/eif/deepface-enclave.eif, deepface-pcr.json
scripts/build-eif.sh --workload di         # -> target/eif/di-enclave.eif, di-pcr.json

# Build or inspect only the reproducible OCI boundary.
nix build .#di-oci
skopeo inspect \
  "oci:$(readlink -f result):$(nix eval --raw .#packages.x86_64-linux.di-enclave.version)"

# Carrier image that launches an EIF on a Nitro node
docker build -f scripts/Dockerfile.carrier --build-arg EIF_FILE=di-enclave.eif target/eif
```

`GIT_HUB_TOKEN` and `HUGGING_FACE_TOKEN` are both `deepface`-only. A build now resolves one
enclave's workspace rather than the whole repository, and nothing in `di`'s graph is private.

The converter itself is also pinned by Nix: `nix build .#nitro-cli` builds AWS nitro-cli
v1.4.2 from source and bundles the matching AWS kernel, init, NSM, and LinuxKit blobs.

`di-enclave` exits non-zero on start, so its EIF builds and measures but will not stay
running, until the boot sequence lands.

## Enclave assignment

`POST /v1/enclave-assignment` returns the enclave's encryption-key attestation and nothing
else:

```json
{ "attestation": "<base64 COSE_Sign1>" }
```

The enclave's identity (`module_id`) and expiry (the leaf certificate's `notAfter`) are read
from the document *after* verifying it, never from fields the untrusted host could set.

Documents are served from an in-enclave cache. After boot starts background refresh, a task
re-attests every 10 minutes (`MAX_CACHED_AGE`); requests always receive the last successful
document immediately, including past `MAX_CACHED_AGE` if a refresh is in flight or has failed.
Attest errors do not block serving until the document is older than `MAX_SERVABLE_AGE` (1 hour),
at which point the refresh task exits and the enclave process exits. The cache is boot-scoped,
so a restart takes it along and there is nothing for the host to invalidate.

`deepface-client` verifies the document — the COSE signature, the certificate chain up to the
pinned AWS Nitro root, and the expected measurements. It is configured by a JSON file, in the
shape `world-id-protocol` uses for an authenticator:

```json
{
  "host_url": "http://localhost:8000",
  "allowed_pcr_configs": [
    [{ "index": 0, "value": "<PCR0 hex from deepface-pcrs.json>" }]
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

`deepface-e2e` reads that file from `VERIFIER_CONFIG` and fetches its encryption key
through the host, exercising the assignment route and the client together:

```bash
VERIFIER_CONFIG=./client.json cargo run --bin deepface-e2e -- <credential> <live> <challenge>
```

## Embedding extraction

`POST /v1/extract-embedding` extracts a versioned Face Engine embedding from one enrollment image.
Like the match flow, the image and result are sealed end-to-end; the host relays them without being
able to inspect either one:

```json
{ "ciphertext": "<base64 enc || ciphertext>" }
```

The sealed request contains `ExtractEmbeddingInputs`: the channel version and raw image bytes. A
successful sealed response contains the vector together with its embedding type, embedding version,
and inference backend. Keeping that metadata beside the vector lets a later consumer reject an
incompatible model output rather than silently comparing unlike embeddings.

```json
{ "response_ciphertext": "<base64 nonce || ciphertext>" }
```

Image decode, quality, and embedding-generation failures are returned as a sealed
`ExtractEmbeddingResult::Failed`; the HTTP response is still `200`. An unopenable request returns
`409 reassign_required`, malformed base64 returns `400 invalid_request`, and enclave availability
or internal failures use the same statuses as `/v1/matches`.

## Matches

`POST /v1/matches` compares a credential image against a live frame and the RP's challenge
frame. The host relays but cannot read either input:

```json
{ "challenge_image_id": "<uuid>", "ciphertext": "<base64 enc || ciphertext>" }
```

`ciphertext` is the match inputs sealed to the enclave's attested encryption key — both
images, `hashes.json`, and the AES-256-GCM key and IV for the challenge image. The challenge
image itself never travels: it is uploaded encrypted, and the host fetches that blob holding no
key for it. A swapped object therefore fails inside the enclave rather than changing the result.

The sealed payload also carries an optional `light_guard_image`, a second liveness frame. Omitting
it selects vanilla mode, the flow described here. Sending one selects LightGuard — challenge-response
spoof detection — which **is not implemented**: the enclave panics on such a request today.

```json
{ "response_ciphertext": "<base64 nonce || ciphertext>" }
```

The sealed response carries either a `COSE_Sign1` match statement or the reason no statement was
issued. A statement travels with the signing key's attestation sealed beside it, since that
document is the only thing saying which enclave signed it. A rejection carries no document.
Only the requester can open any of it — a second channel to the same enclave key cannot.

The signing key's attestation is a separate document from the encryption key's on purpose: it
outlives the exchange and is carried into the `DeepFace` proof, while the encryption key's is
transport setup discarded with the channel.


The host learns only that the enclave answered. Once a request has been opened there is a sealed
channel to reply on, so everything the enclave discovers from that point — a malformed payload, an
unusable `hashes.json`, an image refused on quality grounds, a below-threshold score, a challenge
blob that would not decrypt — travels inside `response_ciphertext`. None of it reaches the status
code.

| Status | Meaning |
| --- | --- |
| `200` | The enclave answered; the sealed payload holds the outcome |
| `409` `reassign_required` | The request did not open, so there was no channel to reply on; re-assign and re-seal, once |
| `400` `invalid_challenge_id` | The id was not a UUID, and was rejected before any request was made |
| `502` `challenge_fetch_failed` | The challenge image could not be fetched |
| `500` `internal_error` | Enclave fault |

`409` is the only input failure with a status of its own, because with no channel open there is
nothing to seal a reply into. Everything else the host might want — how often matches fail, how often
the RP's objects are stale — has to come from enclave-side metrics rather than from status codes.

### The challenge fetch

The caller names an object, not a destination. `CHALLENGE_IMAGE_BASE_URL` — an HTTPS URL ending in
`/`, e.g. `https://<bucket>.s3.<region>.amazonaws.com/challenges/` — is the only thing deciding
where a fetch goes, and the id is resolved against it after parsing as a UUID. Nothing a client
sends can change the host, scheme, port or path, which is what closes the SSRF surface rather than
filtering it. There is no default: without the variable the host refuses to start.

The id is a locator, not a capability. Presenting someone else's id yields a blob that will not
decrypt under the key in the caller's own sealed payload, and the RP's `challenger_image_hash`
check rejects the resulting proof regardless.

Around that: no redirect following, a 5s deadline, and a 4 MiB ceiling enforced while streaming.

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

Install Rust and the components these workspaces use:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup component add rustfmt clippy
for ws in . deepface/enclave di/enclave; do cargo test --manifest-path "$ws/Cargo.toml" --all; done
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

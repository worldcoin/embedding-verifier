#!/bin/bash
set -euo pipefail

# Build the DeepFace enclave EIF and emit its PCR measurements. Needs Linux
# x86_64 + Docker; Nitro hardware is only required to run the enclave, not
# build it.
#
# Usage: scripts/build-eif.sh [--from-image] [output-dir]
#        (output-dir defaults to target/eif)
# Outputs: embedding-verifier-enclave.eif, pcrs.json
# Env: NITRO_CLI_VERSION (default v1.4.2), ENCLAVE_IMAGE_TAG,
#      GIT_HUB_TOKEN (read access to private GitHub dependencies),
#      HUGGING_FACE_TOKEN (read access to private model repositories)
#
# TODO: One enclave is hard-coded here. `di-enclave` needs its own EIF, so the
# Dockerfile, image tag and artifact name all have to become arguments. Renaming
# the artifact is deferred to the deployment work, which consumes it.

if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
  echo "[ERROR] EIF builds require Linux x86_64 (got $(uname -s)/$(uname -m))." >&2
  exit 1
fi

NITRO_CLI_VERSION="${NITRO_CLI_VERSION:-v1.4.2}"
ENCLAVE_IMAGE_TAG="${ENCLAVE_IMAGE_TAG:-embedding-verifier-enclave:local}"

usage() {
  printf '%s\n' \
    "Usage: scripts/build-eif.sh [--from-image] [output-dir]" \
    "" \
    "Build the enclave EIF and emit its PCR measurements." \
    "" \
    "Options:" \
    "  --from-image  Convert ENCLAVE_IMAGE_TAG without building it first." \
    "  -h, --help    Show this help."
}

build_image=true
out_dir="target/eif"
output_dir_provided=false
while (( $# > 0 )); do
  case "$1" in
    --from-image)
      build_image=false
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "[ERROR] Unknown option: $1" >&2
      exit 2
      ;;
    *)
      if [[ "$output_dir_provided" == "true" ]]; then
        echo "[ERROR] Only one output directory may be provided." >&2
        exit 2
      fi
      out_dir="$1"
      output_dir_provided=true
      ;;
  esac
  shift
done

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"

if [[ "$build_image" == "true" ]]; then
  echo "[1/3] Building enclave container image ($ENCLAVE_IMAGE_TAG)..."
  if [[ -z "${GIT_HUB_TOKEN:-}" ]]; then
    echo "[ERROR] GIT_HUB_TOKEN is required to fetch private GitHub dependencies." >&2
    exit 1
  fi

  if [[ -z "${HUGGING_FACE_TOKEN:-}" ]]; then
    echo "[ERROR] HUGGING_FACE_TOKEN is required to download private models." >&2
    exit 1
  fi

  docker build \
    --secret id=GITHUB_TOKEN,env=GIT_HUB_TOKEN \
    --secret id=HUGGING_FACE_TOKEN,env=HUGGING_FACE_TOKEN \
    -t "$ENCLAVE_IMAGE_TAG" \
    -f deepface/enclave/Dockerfile \
    .
else
  echo "[1/3] Using existing enclave container image ($ENCLAVE_IMAGE_TAG)..."
  if ! docker image inspect "$ENCLAVE_IMAGE_TAG" >/dev/null 2>&1; then
    echo "[ERROR] Enclave container image not found locally: $ENCLAVE_IMAGE_TAG" >&2
    exit 1
  fi
fi

echo "[2/3] Building nitro-cli $NITRO_CLI_VERSION..."
nitro_cli_dir="$out_dir/aws-nitro-enclaves-cli-$NITRO_CLI_VERSION"
nitro_cli="$nitro_cli_dir/target/release/nitro-cli"
if [ ! -x "$nitro_cli" ]; then
  rm -rf "$nitro_cli_dir"
  git clone --depth 1 --branch "$NITRO_CLI_VERSION" \
    https://github.com/aws/aws-nitro-enclaves-cli "$nitro_cli_dir"
  cargo build --release --bin nitro-cli --manifest-path "$nitro_cli_dir/Cargo.toml"
fi

echo "[3/3] Converting to EIF..."
eif_path="$out_dir/embedding-verifier-enclave.eif"
build_json="$out_dir/build-enclave.json"
NITRO_CLI_BLOBS="$nitro_cli_dir/blobs/x86_64" \
NITRO_CLI_ARTIFACTS="$out_dir/artifacts" \
  "$nitro_cli" build-enclave \
    --docker-uri "$ENCLAVE_IMAGE_TAG" \
    --output-file "$eif_path" | tee "$build_json"

jq '.Measurements' "$build_json" > "$out_dir/pcrs.json"

echo
echo "EIF:  $eif_path"
echo "PCRs: $out_dir/pcrs.json"
jq . "$out_dir/pcrs.json"

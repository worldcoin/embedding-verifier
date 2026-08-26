#!/bin/bash
set -euo pipefail

# Build a workload's enclave EIF and emit its PCR measurements. Needs Linux
# x86_64 + Docker; Nitro hardware is only required to run the enclave, not
# build it.
#
# Usage: scripts/build-eif.sh [--workload <name>] [--from-image] [output-dir]
#        (workload defaults to deepface, output-dir to target/eif)
# Outputs: <workload>-enclave.eif, <workload>-pcrs.json
# Env: NITRO_CLI_VERSION (default v1.4.2), ENCLAVE_IMAGE_TAG,
#      GIT_HUB_TOKEN (read access to private GitHub dependencies),
#      HUGGING_FACE_TOKEN (read access to private model repositories)
#
# GIT_HUB_TOKEN applies to every workload: cargo resolves the whole workspace, so
# face-engine is fetched even by workloads that do not use it. HUGGING_FACE_TOKEN
# is deepface-only.

NITRO_CLI_VERSION="${NITRO_CLI_VERSION:-v1.4.2}"

# A new workload is a directory with an enclave/Dockerfile plus an entry here.
WORKLOADS=("deepface" "di")

usage() {
  printf '%s\n' \
    "Usage: scripts/build-eif.sh [--workload <name>] [--from-image] [output-dir]" \
    "" \
    "Build a workload's enclave EIF and emit its PCR measurements." \
    "" \
    "Options:" \
    "  --workload <name>  Which enclave to build: ${WORKLOADS[*]} (default deepface)." \
    "  --from-image       Convert ENCLAVE_IMAGE_TAG without building it first." \
    "  -h, --help         Show this help."
}

build_image=true
workload="deepface"
out_dir="target/eif"
output_dir_provided=false
while (( $# > 0 )); do
  case "$1" in
    --workload)
      if (( $# < 2 )); then
        echo "[ERROR] --workload needs a value." >&2
        exit 2
      fi
      workload="$2"
      shift
      ;;
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

if [[ ! " ${WORKLOADS[*]} " == *" $workload "* ]]; then
  echo "[ERROR] Unknown workload: $workload (expected one of: ${WORKLOADS[*]})" >&2
  exit 2
fi

# After arg parsing, so --help and a bad --workload work on any host.
if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
  echo "[ERROR] EIF builds require Linux x86_64 (got $(uname -s)/$(uname -m))." >&2
  exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

dockerfile="$workload/enclave/Dockerfile"
if [[ ! -f "$dockerfile" ]]; then
  echo "[ERROR] No enclave Dockerfile for '$workload' at $dockerfile." >&2
  exit 1
fi
ENCLAVE_IMAGE_TAG="${ENCLAVE_IMAGE_TAG:-embedding-verifier-$workload-enclave:local}"

mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"

if [[ "$build_image" == "true" ]]; then
  echo "[1/3] Building $workload enclave container image ($ENCLAVE_IMAGE_TAG)..."

  if [[ -z "${GIT_HUB_TOKEN:-}" ]]; then
    echo "[ERROR] GIT_HUB_TOKEN is required to fetch private GitHub dependencies." >&2
    exit 1
  fi

  secret_args=(--secret "id=GITHUB_TOKEN,env=GIT_HUB_TOKEN")

  if [[ "$workload" == "deepface" ]]; then
    if [[ -z "${HUGGING_FACE_TOKEN:-}" ]]; then
      echo "[ERROR] HUGGING_FACE_TOKEN is required to download private models." >&2
      exit 1
    fi

    secret_args+=(--secret "id=HUGGING_FACE_TOKEN,env=HUGGING_FACE_TOKEN")
  fi

  docker build \
    "${secret_args[@]}" \
    -t "$ENCLAVE_IMAGE_TAG" \
    -f "$dockerfile" \
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
eif_path="$out_dir/$workload-enclave.eif"
build_json="$out_dir/$workload-build-enclave.json"
NITRO_CLI_BLOBS="$nitro_cli_dir/blobs/x86_64" \
NITRO_CLI_ARTIFACTS="$out_dir/artifacts" \
  "$nitro_cli" build-enclave \
    --docker-uri "$ENCLAVE_IMAGE_TAG" \
    --output-file "$eif_path" | tee "$build_json"

pcrs_path="$out_dir/$workload-pcrs.json"
jq '.Measurements' "$build_json" > "$pcrs_path"

echo
echo "EIF:  $eif_path"
echo "PCRs: $pcrs_path"
jq . "$pcrs_path"

#!/bin/bash
set -euo pipefail

# Build a workload's enclave EIF and emit its PCR measurements.
#
# The EIF is assembled entirely inside Nix (see flake.nix): enclave binary, models,
# rootfs, ramdisks and EIF layout all come from pinned flake inputs, so the PCRs
# depend on nothing but the commit being built — no Docker daemon, no nitro-cli.
# Any machine building the same commit measures the same values.
#
# Needs x86_64-linux, either natively or through a remote builder.
#
# Usage: scripts/build-eif.sh [--workload <name>] [output-dir]
#        (workload defaults to deepface, output-dir to target/eif)
#
# Outputs in <output-dir>:
#   <workload>-enclave.eif   the enclave image
#   <workload>-pcr.json      raw PCR output from eif_build
#   measurements.json        measurements.json with the freshly measured PCRs
#                            substituted into this workload's entry
#
# Env: HUGGING_FACE_TOKEN (deepface only — read access to the model repositories).

# A new workload is an entry here plus a `<name>-eif` output in flake.nix.
WORKLOADS=("deepface" "di")

usage() {
  printf '%s\n' \
    "Usage: scripts/build-eif.sh [--workload <name>] [output-dir]" \
    "" \
    "Build a workload's enclave EIF and emit its PCR measurements." \
    "" \
    "Options:" \
    "  --workload <name>  Which enclave to build: ${WORKLOADS[*]} (default deepface)." \
    "  -h, --help         Show this help."
}

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

command -v nix >/dev/null || {
  echo "[ERROR] nix not found. The EIF is built by flake.nix; there is no fallback," >&2
  echo "        because a different build path means different PCRs." >&2
  exit 1
}

if [[ "$workload" == "deepface" && -z "${HUGGING_FACE_TOKEN:-}" ]]; then
  echo "[ERROR] HUGGING_FACE_TOKEN is required to fetch the face models." >&2
  exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"

# Fetch the models outside Nix and add them to the store under the fixed-output hash
# flake.nix declares, which leaves the fetch in the build already satisfied. The token
# is used here and nowhere else, so it never reaches a derivation or the store.
if [[ "$workload" == "deepface" ]]; then
  echo "[1/3] Fetching face models..."
  models_json="$(nix eval --json .#faceModels)"
  work_dir="$(mktemp -d)"
  trap 'rm -rf "$work_dir"' EXIT

  for file in $(jq -r 'keys[]' <<<"$models_json"); do
    store_path="$(jq -r --arg f "$file" '.[$f].storePath' <<<"$models_json")"
    if nix path-info "$store_path" >/dev/null 2>&1; then
      echo "  $file: already in the store"
      continue
    fi

    url="$(jq -r --arg f "$file" '.[$f].url' <<<"$models_json")"
    expected="$(jq -r --arg f "$file" '.[$f].hash' <<<"$models_json")"
    echo "  $file: downloading"
    # --fail so an HTML error page never gets hashed as if it were a model. The token goes
    # to huggingface.co only; curl does not follow it across the redirect to the CDN, which
    # carries its own signature. It arrives through --config so it never appears in argv,
    # where anyone running `ps` on the build host could read it.
    printf 'header = "Authorization: Bearer %s"\n' "$HUGGING_FACE_TOKEN" |
      curl --proto '=https' --tlsv1.2 -sSfL \
        --retry 3 --retry-all-errors --connect-timeout 10 --max-time 600 \
        --config - \
        -o "$work_dir/$file" "$url"

    observed="$(nix hash file --type sha256 --base16 "$work_dir/$file")"
    if [[ "$observed" != "$expected" ]]; then
      echo "[ERROR] checksum mismatch for $file: expected $expected, got $observed" >&2
      exit 1
    fi

    added="$(nix-store --add-fixed sha256 "$work_dir/$file")"
    if [[ "$added" != "$store_path" ]]; then
      echo "[ERROR] $file landed at $added, but the build expects $store_path" >&2
      exit 1
    fi
  done
fi

echo "[2/3] Building $workload EIF..."
if ! eif_store=$(nix build ".#${workload}-eif" --no-link --print-out-paths); then
  echo >&2
  echo "[ERROR] nix build failed. On a 'platform mismatch' for x86_64-linux, this host" >&2
  echo "        needs a remote builder for that system." >&2
  exit 1
fi

install -m 0644 "$eif_store/image.eif" "$out_dir/$workload-enclave.eif"
install -m 0644 "$eif_store/pcr.json" "$out_dir/$workload-pcr.json"

echo "[3/3] Recording measurements..."
# A whole measurements.json rather than the PCRs alone, so the output is directly
# comparable to the committed file. The other workload's entry is carried over
# untouched — this build is in no position to recompute it.
jq -S --slurpfile built "$out_dir/$workload-pcr.json" --arg workload "$workload" \
  '.[$workload] = {pcr0: ("0x" + $built[0].PCR0),
                   pcr1: ("0x" + $built[0].PCR1),
                   pcr2: ("0x" + $built[0].PCR2)}' \
  "$repo_root/measurements.json" > "$out_dir/measurements.json"

echo
echo "EIF:          $out_dir/$workload-enclave.eif"
echo "Measurements: $out_dir/measurements.json"
jq . "$out_dir/measurements.json"

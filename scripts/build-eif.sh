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
# Usage: scripts/build-eif.sh [--workload <name>] [--allow-dirty] [output-dir]
#        (workload defaults to deepface, output-dir to target/eif)
#
# Outputs in <output-dir>:
#   <workload>-enclave.eif   the enclave image
#   <workload>-pcr.json      raw PCR output from eif_build
#   measurements.json        measurements.json with the freshly measured PCRs
#                            substituted into this workload's entry
#
# Env: HUGGING_FACE_TOKEN (deepface only, and only when a model is not in the store
#      yet — read access to the model repositories).

# A new workload is an entry here plus a `<name>-eif` output in flake.nix.
WORKLOADS=("deepface" "di")

# Workloads whose enclave graph reaches a private repository.
PRIVATE_DEP_WORKLOADS=("deepface")

usage() {
  printf '%s\n' \
    "Usage: scripts/build-eif.sh [--workload <name>] [--allow-dirty] [output-dir]" \
    "" \
    "Build a workload's enclave EIF and emit its PCR measurements." \
    "" \
    "Options:" \
    "  --workload <name>  Which enclave to build: ${WORKLOADS[*]} (default deepface)." \
    "  --allow-dirty      Build from a dirty tree. The PCRs then describe no commit." \
    "  -h, --help         Show this help."
}

workload="deepface"
out_dir="target/eif"
output_dir_provided=false
allow_dirty=false
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
    --allow-dirty)
      allow_dirty=true
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

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

# A git flake is built from tracked files at their committed content, so uncommitted work is
# measured out of the EIF without saying so. Measurements that describe no commit are worse
# than no measurements.
if [[ -n "$(git status --porcelain)" ]]; then
  if [[ "$allow_dirty" != "true" ]]; then
    echo "[ERROR] The working tree is dirty, and Nix builds this flake from committed" >&2
    echo "        files only — the PCRs would describe no commit. Commit first, or pass" >&2
    echo "        --allow-dirty if the measurements are throwaway." >&2
    git status --short >&2
    exit 1
  fi
  echo "[WARN] Dirty tree: building from committed files only. These PCRs describe no"
  echo "       commit — do not register them with a client."
fi

mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

# Fetch the models outside Nix and add them to the store under the fixed-output hash
# flake.nix declares, which leaves the fetch in the build already satisfied. The token
# is used here and nowhere else, so it never reaches a derivation or the store.
#
# --no-update-lock-file on the flake calls below: an input added to flake.nix without a
# matching `nix flake update` would otherwise be resolved to whatever upstream serves right
# now, and the lock silently rewritten. The PCRs must follow the committed lock or nothing.
if [[ "$workload" == "deepface" ]]; then
  echo "[1/3] Fetching face models..."
  models_json="$(nix eval --json --no-update-lock-file .#faceModels)"

  for file in $(jq -r 'keys[]' <<<"$models_json"); do
    store_path="$(jq -r --arg f "$file" '.[$f].storePath' <<<"$models_json")"
    if nix path-info "$store_path" >/dev/null 2>&1; then
      echo "  $file: already in the store"
      continue
    fi

    if [[ -z "${HUGGING_FACE_TOKEN:-}" ]]; then
      echo "[ERROR] $file is not in the store and HUGGING_FACE_TOKEN is unset." >&2
      echo "        The token is only needed to fetch a model that is missing; rebuilding" >&2
      echo "        a commit whose models are already in the store needs neither." >&2
      exit 1
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
if ! eif_store=$(nix build ".#${workload}-eif" --no-update-lock-file --no-link --print-out-paths); then
  echo >&2
  echo "[ERROR] nix build failed; the error above says why. A 'platform mismatch' for" >&2
  echo "        x86_64-linux means this host needs a remote builder for that system." >&2
  exit 1
fi

install -m 0644 "$eif_store/image.eif" "$out_dir/$workload-enclave.eif"
install -m 0644 "$eif_store/pcr.json" "$out_dir/$workload-pcr.json"

echo "[3/3] Recording measurements..."
# pcr.json is the tail of eif_build's stdout, so a change in its output format arrives here
# as a missing key rather than an error — and jq folds a missing key into the string "0x".
# Registering "0x" with a client would accept every attestation, so check the shape first.
for pcr in PCR0 PCR1 PCR2; do
  value="$(jq -r --arg k "$pcr" '.[$k] // ""' "$out_dir/$workload-pcr.json")"
  if [[ ! "$value" =~ ^[0-9a-f]{96}$ ]]; then
    echo "[ERROR] $workload-pcr.json holds no usable $pcr (got '$value')." >&2
    echo "        eif_build's output format may have changed; do not register these." >&2
    exit 1
  fi
done

# A whole measurements.json rather than the PCRs alone, so the output is directly
# comparable to the committed file. The other workload's entry is carried over
# untouched — this build is in no position to recompute it. An earlier run's output in
# $out_dir wins over the committed file, so refreshing both workloads in turn keeps both
# fresh values instead of reverting the first.
base="$repo_root/measurements.json"
if [[ -f "$out_dir/measurements.json" ]]; then
  base="$out_dir/measurements.json"
fi

# Through the scratch dir: $out_dir can be the repo root, and redirecting straight to the
# destination truncates it before jq opens it — which would empty the committed file.
jq -S --slurpfile built "$out_dir/$workload-pcr.json" --arg workload "$workload" \
  '.[$workload] = {pcr0: ("0x" + $built[0].PCR0),
                   pcr1: ("0x" + $built[0].PCR1),
                   pcr2: ("0x" + $built[0].PCR2)}' \
  "$base" > "$work_dir/measurements.json"
install -m 0644 "$work_dir/measurements.json" "$out_dir/measurements.json"

echo
echo "EIF:          $out_dir/$workload-enclave.eif"
echo "Measurements: $out_dir/measurements.json"
jq . "$out_dir/measurements.json"

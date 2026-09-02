#!/bin/bash
set -euo pipefail

# Record what a workload's EIF is built from, so a PCR drift can be attributed.
#
# The build has two halves with very different guarantees. Nix produces the OCI image and
# the pinned nitro-cli, and those are content-addressed: the hashes below pin them exactly.
# AWS nitro-cli then converts the OCI image to an EIF through a Docker daemon, and nothing
# in that step is content-addressed.
#
# That split is the point of this file. If two builds agree on every hash here but disagree
# on the PCRs, the divergence is in the conversion, not in anything Nix pinned — which is
# the one conclusion the PCRs alone can never give you.
#
# Usage: scripts/closure-hashes.sh <workload> [output-file] [eif-file]
#        (output-file defaults to closure-<workload>.txt; the EIF is hashed if given)

if (( $# < 1 || $# > 3 )); then
  echo "Usage: scripts/closure-hashes.sh <workload> [output-file] [eif-file]" >&2
  exit 2
fi

workload="$1"
out_file="${2:-closure-$workload.txt}"
eif_file="${3:-}"

command -v nix >/dev/null || {
  echo "[ERROR] nix not found; the layer hashes come from the Nix store." >&2
  exit 1
}

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

# The EIF builder is a wrapper script, so its closure carries nitro-cli, its blobs and the
# OCI image it converts — everything Nix contributes to the measurement, and nothing else.
builder_drv=$(nix path-info --derivation --no-update-lock-file ".#${workload}-eif")
{
  echo "# nix-pinned inputs"
  for d in $(nix-store --query --references "$builder_drv" | grep '\.drv$'); do
    for o in $(nix-store --query --outputs "$d"); do
      if nix-store --query --hash "$o" >/dev/null 2>&1; then
        printf '%s  %s\n' "$(nix-store --query --hash "$o")" "$(basename "$o")"
      fi
    done
  done
  for out in "${workload}-enclave" "${workload}-oci" "${workload}-eif"; do
    p=$(nix build --no-link --no-update-lock-file --print-out-paths ".#${out}")
    printf '%s  %s\n' "$(nix-store --query --hash "$p")" "$(basename "$p")"
  done
} | sort -u -k2 > "$out_file"

# The OCI layout is the boundary Nix guarantees. Hashing its manifest and config separately
# from the store path distinguishes "Nix produced different bytes" from "the same bytes were
# converted differently".
oci_store=$(nix build --no-link --no-update-lock-file --print-out-paths ".#${workload}-oci")
{
  echo "# oci layout"
  find "$oci_store" -type f -printf '%P\n' 2>/dev/null | sort | while read -r f; do
    printf '%s  oci/%s\n' "$(sha256sum "$oci_store/$f" | cut -d' ' -f1)" "$f"
  done
} >> "$out_file"

# Localize a binary difference without shipping the binary: the enclave links private
# face-engine code. Size plus per-chunk hashes say whether the divergence is a few
# embedded bytes or a whole-layout shift.
bin="$(nix build --no-link --no-update-lock-file --print-out-paths \
       ".#${workload}-enclave")/bin/${workload}-enclave"
{
  echo "# enclave binary"
  echo "size $(stat -c%s "$bin")"
} >> "$out_file"
split -b 1M -d -a 3 "$bin" "$work_dir/chunk."
(cd "$work_dir" && sha256sum chunk.*) >> "$out_file"
rm -f "$work_dir"/chunk.*

# The conversion output. Not Nix-pinned, and therefore the thing most likely to differ.
if [[ -n "$eif_file" ]]; then
  {
    echo "# eif (produced by nitro-cli, outside the nix closure)"
    printf '%s  eif/%s\n' "$(sha256sum "$eif_file" | cut -d' ' -f1)" "$(basename "$eif_file")"
    echo "size $(stat -c%s "$eif_file")"
  } >> "$out_file"
fi

echo "Layer hashes: $out_file"

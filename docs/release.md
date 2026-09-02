# Releasing an enclave

Each workload releases on its own tag: `deepface/vX.Y.Z`, `di/vX.Y.Z`. The tag is handled by
[`.github/workflows/release.yml`](../.github/workflows/release.yml).

## Why the tags are split

`flake.nix` reads the version from `<workload>/enclave/Cargo.toml` and builds it into the EIF, so
**a version bump is a PCR rotation**. Under one repo-wide tag, a deepface change would rotate di's
PCR0 too, and every client pinning di would have to re-register a measurement for a workload that
did not change.

## What a release produces

| Artifact | Notes |
|:---|:---|
| `manifest.json` | Binds the commit, the pinned flake inputs, the PCRs, the model hashes and the image digests. This is what the deploy reads `ENCLAVE_PCR0` from. |
| `<workload>-enclave.eif` | The enclave image itself |
| `ghcr.io/worldcoin/embedding-verifier-<workload>-enclave-oci` | The measured image before conversion — the one artifact an outsider can verify against |
| `<workload>-pcr.json` | Raw `eif_build` output |
| `closure-<workload>.txt` | narHash of every layer the EIF is assembled from |
| `SHA256SUMS` | Covers every asset above; one build attestation is keyed to it |
| `ghcr.io/worldcoin/embedding-verifier[-di-host]:vX.Y.Z` | The host image |
| `ghcr.io/worldcoin/embedding-verifier-<workload>-enclave-eif:vX.Y.Z` | Carrier image for the enclave sidecar |

## Cutting a release

1. **Bump the version.** Edit `package.version` in `<workload>/enclave/Cargo.toml`, then refresh
   the lockfile beside it:
   ```
   cargo update --manifest-path <workload>/enclave/Cargo.toml --workspace
   ```
2. **Re-measure.** The bump moved PCR0, so `measurements.json` is now stale. Either build locally
   (below) or push the bump and let CI tell you: `verify-measurements.yml` fails and writes the
   fresh values into the job summary and a `fresh-measurements-<workload>` artifact. Paste them in.
3. **One PR** carrying the version bump *and* the new `measurements.json`. Splitting them lets the
   repo record a version whose measurement nobody checked. `verify-measurements.yml` gates it.
4. **Tag and push:**
   ```
   git tag deepface/v0.2.0 <sha-on-main>
   git push origin deepface/v0.2.0
   ```
5. **Wait for the gate.** Two builds run first — about 90 minutes each, in parallel. Nothing is
   published unless they agree.
6. **Review the draft**, check the PCR table, publish. The draft is the last human step: the
   release is created unpublished, so nothing is live until someone publishes it.

> The `release` GitHub environment carries no protection rules today, so `approve-publish`
> passes straight through and images are pushed as soon as the reproducibility gate is green.
> To require a human before anything is published, add required reviewers to that environment —
> a settings change, no workflow edit.

To exercise the pipeline without a tag, dispatch it:

```
gh workflow run release.yml -f workload=di -f ref=main -f dry_run=true
```

A dry run builds, verifies and publishes nothing.

## How the measurement is produced

Two steps with different guarantees, and the difference matters:

1. **Nix builds an OCI image** (`nix build .#<workload>-oci`) from the enclave binary, the
   models and `pkgs.cacert`, with `dockerTools.buildLayeredImage` at a fixed creation time.
   This half is content-addressed: same commit, same bytes, anywhere.
2. **AWS nitro-cli converts that image to an EIF.** `skopeo` loads the OCI layout into a
   Docker daemon and `nitro-cli build-enclave` runs its bundled LinuxKit over it. nitro-cli
   v1.4.2 and its kernel, init, NSM and LinuxKit blobs are pinned by `nix/nitro-cli.nix`,
   but **the Docker daemon is the host's and is not pinned**.

PCR0 covers the kernel, the cmdline and both ramdisks; PCR1 the kernel and boot ramdisk;
PCR2 the application ramdisk. The EIF metadata section — which carries a wall-clock
`BuildTime` — is *not* measured, so the timestamp does not reach a PCR.

Step 2 is the reason `release.yml` builds every release twice, on two different runner
images, and refuses to publish unless both agree. The Docker daemon sits on the measured
path; the double build is what turns "should not matter" into evidence for this commit.

## Building and measuring locally

Needs x86_64-linux with Nix **and a running Docker daemon**, plus read access to
`worldcoin/biometric-engines` and a `HUGGING_FACE_TOKEN` for deepface. Expect ~90 minutes
cold for deepface.

```
scripts/build-eif.sh --workload deepface target/eif
diff <(jq -S . measurements.json) <(jq -S . target/eif/measurements.json)
scripts/closure-hashes.sh deepface closure-deepface.txt target/eif/deepface-enclave.eif
```

If your PCRs differ from a published release, compare `closure-<workload>.txt` first. It
separates the Nix-pinned inputs from the EIF that came out of the conversion, so a mismatch
says which half moved before you start bisecting.

`di` needs neither the token nor the models — it reaches no private repository.

## What rotates a PCR

- Any `*.rs`, `Cargo.toml`, `Cargo.lock`, `*.yaml`, `*.der` or `*.b64` file in the workload's
  crate graph — that is the exact filter `nix/enclave-binaries.nix`'s file set applies
- The enclave's `Cargo.lock`, including a transitive bump
- `rust-toolchain.toml`, `flake.lock`, and the face-model revisions in `nix/face-models.nix`
- **The `nix/` derivations themselves.** Every string in them is measured; a no-op edit moves
  PCR0 and PCR2. Treat any change under `nix/` as a release event.
- **The pinned nitro-cli version.** Its kernel and init blobs are PCR0 and PCR1 inputs, so
  bumping `nitro-cli-src` rotates measurements for both workloads at once.

A README, a workflow or a doc cannot move a PCR. They are outside the fileset.

## Rotating a measurement in production

`deepface/client/src/config.rs` accepts an attestation matching **any one** entry of
`allowed_pcr_configs` in full, so several enclave versions can be trusted at once. Use that
overlap:

1. Publish the new release. Add its PCR0 to the client allow-list **alongside** the old one.
2. Wait for clients to pick up the new allow-list. Until they have, deploying the new enclave
   alone would break every client still pinning only the old measurement.
3. Deploy the new enclave. The host pins one PCR0 — its own local sidecar's — so it moves with
   the deployment; the overlap exists for clients, not for the host.
4. Retire the old measurement from the allow-list once nothing is verifying against it.

Registry rows carry the `pcr0` they were attested under, so a withdrawn image can be revoked in
bulk. That path is not built yet: nothing sets `KeyStatus::Revoked`, the IAM policy grants no
`UpdateItem`, and a bulk revoke needs a GSI on `pcr0`.

## Re-deriving a PCR without building from source

`deepface-enclave` links private face-engine code, so "check out the tag and rebuild" is not
available to most people, and a measurement nobody outside can reproduce is worth little.

The published OCI image closes that gap. It is the exact input the EIF is converted from, so
converting it with the pinned nitro-cli must yield the release's PCRs:

```
skopeo copy docker://<images.enclaveOci from manifest.json> oci:enclave:<version>
nix run github:worldcoin/embedding-verifier/<gitSha>#nitro-cli -- \
  build-enclave --docker-uri <loaded image> --output-file enclave.eif
```

This needs a Docker daemon and nothing private. It does not prove the image matches the
source — only someone with face-engine access can check that — but it does prove the
published PCRs describe the published image, which is what a client is pinning.

## Verifying a published release

```
gh release download deepface/v0.2.0 -R worldcoin/embedding-verifier
gh attestation verify manifest.json --repo worldcoin/embedding-verifier \
   --signer-workflow worldcoin/embedding-verifier/.github/workflows/release.yml
sha256sum -c SHA256SUMS
```

The attestation binds the assets to the workflow and commit that produced them. Then reproduce
the measurements from source and compare against `manifest.json`.

## Notes

- `di/host` and `di/enclave` are skeletons that exit with a failure code. A `di/v*` tag exercises
  the release pipeline; it does not ship a working service.
- The EIF is published publicly, and the deepface enclave links private face-engine code. Confirm
  with the `biometric-engines` owners before the first `deepface/v*` tag.

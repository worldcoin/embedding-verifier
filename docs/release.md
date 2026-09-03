# Releasing an enclave

Each workload releases on its own tag: `deepface/vX.Y.Z`, `di/vX.Y.Z`. The tag is handled by
[`.github/workflows/release.yml`](../.github/workflows/release.yml).

## Cutting a release

1. **Bump the version.** Edit `workspace.package.version` in the root `Cargo.toml`, then refresh
   the root lockfile:
   ```
   cargo update --workspace
   ```
2. **Tag and push:**
   ```
   git tag deepface/v0.2.0 <sha-on-main>
   git push origin deepface/v0.2.0
   ```
3. **Wait for the gate.** Two builds run first — about 90 minutes each, in parallel. Nothing is
   published unless they agree.
4. **Review the draft**, check the PCR table, publish. The draft is the last human step: the
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

## Building and measuring locally

Needs x86_64-linux with Nix, plus read access to `worldcoin/biometric-engines` and a
`HUGGING_FACE_TOKEN` for deepface. Expect ~90 minutes cold for deepface.

```
scripts/build-eif.sh --workload deepface target/eif
jq . target/eif/deepface-pcr.json
```

`di` needs neither the token nor the models — it reaches no private repository.

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

```
# both values come from manifest.json: .images.enclaveOci and .gitSha
skopeo --insecure-policy copy \
  docker://ghcr.io/worldcoin/embedding-verifier-deepface-enclave-oci@sha256:<digest> \
  docker-daemon:embedding-verifier-deepface-enclave:<version>

nix run github:worldcoin/embedding-verifier/<gitSha>#nitro-cli -- build-enclave \
  --docker-uri embedding-verifier-deepface-enclave:<version> \
  --output-file enclave.eif
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

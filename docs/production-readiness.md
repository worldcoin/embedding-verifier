# DeepFace TEE Verifier: production readiness plan

Status as of 2026-09-01, `main` at `4b33034`. Scope is the `deepface` workload: host, enclave,
protocol, client, build, release, infrastructure and operations. `di` is a skeleton and is out
of scope.

Spec: [Spec: DeepFace TEE Verifier v1](https://app.notion.com/p/worldcoin/Spec-DeepFace-TEE-Verifier-v1-3b98614bdf8c80d89063cf03aa0bd290),
last edited 2026-09-01. Three linked specs are referenced but not read for this plan: the
DeepFace protocol spec, the shared biometrics-TEE setup doc, and the key rotation page. The
verifier spec's own §9 and §10 do not exist yet, though §6 and §8 both cite §10 for readiness
semantics and saturation behaviour.

## 1. Where things stand

Working end to end in dev: enclave boot with NSM-attested boot keys, HPKE sealed channel,
3-way match with a signed `COSE_Sign1` statement, host relay with an SSRF-pinned challenge
fetch, DynamoDB signing-key registry with readiness gating, reproducible Nix EIF with PCR
verification in CI, Datadog tracing on the host, one-replica dev deployment on Nitro nodes.

Not yet built at all: model injection, PAD and quality checks, enclave affinity, capacity
shedding, the two internal operational routes, the 2-way flow.

Stated in the code (`deepface/protocol/src/lib.rs`): no external security review, token format
provisional pending protocol sign-off, not production ready.

Dev runs the enclave in `--debug-mode` with all-zero PCRs and the host configured to accept
them, so no attestation check is currently exercised in any deployed environment.

Open issues: #35 affinity, #36 metrics, #41 sandboxing, #42 uniqueness enrollment, #47 model
injection, #48 PAD. Draft PR #49 aligns face-engine configs with iOS.

## 2. Spec versus implementation

These are decisions, not bugs. Each needs a ruling and then either code or a spec edit.

| # | Spec says | Implementation does | Assessment |
|---|---|---|---|
| D1 | `challenge_image_url` travels in the request body. The host fetches it against an allowlist of RP-registered bucket hosts and key prefixes. The RP owns the bucket (§6, §7.2). | `challenge_image_id` is a UUID resolved against one `CHALLENGE_IMAGE_BASE_URL`. Nothing a client sends can move the fetch. | The implementation closes SSRF completely rather than filtering it, which is stronger, but it serves exactly one bucket and so cannot support per-RP buckets. Either the spec moves to a service-owned bucket, or the host needs a registered-RP allowlist. This is a product decision and it blocks the RP integration. A third design exists on `osiris/challenge-push-store` where RPs push to the host. Pick one. |
| D2 | Failures after the request opens are cleartext HTTP: structured `4xx` with a face-engine reason, `422` for a challenge that would not decrypt (§6). | Everything after the request opens is sealed into `response_ciphertext` and the host always returns `200`. | The implementation is the better privacy design and its reasoning is documented in the README: once a channel is open, a status code would tell the untrusted host about a plaintext it cannot read. Recommend keeping it and amending the spec. Until that happens, the client contract in the spec is wrong and anyone building against §6 will build the wrong thing. |
| D3 | Absence of the challenge fields selects a 2-way flow. Inputs accept `credential_image` or `credential_embedding` (§6). | Challenge key and IV are required. `challenger_image_hash` is always a claim. Only `credential_image` is accepted. `match_token.rs` records that v1 is 3-way only. | Confirm whether 2-way and embedding input are v1 scope. If yes it changes `MatchInputs`, the claim set and the token version, so it should land before the token format is frozen. |
| D4 | Routes are `GET /healthz` and `GET /readyz`. | `/health` and `/ready`. | Cosmetic, but the deploy probes point at the implemented names. Align one way and update the Helm values with it. |
| D5 | §4 leans toward unsigned bundles, reasoning that models are open source, and toward leaving `bundle_id` out of the statement. | Nothing built. | Issue #47 says it is not only models but the whole face-engine pipeline binary, which cannot be open sourced. That removes the premise the spec's answer rests on. Both open questions need reopening: bundles should probably be signed with a key baked into the image, and the statement may need to commit to the bundle hash. |
| D6 | Registry TTL is at least the maximum statement lifetime (§5). | 90 days. | Needs the actual number from the protocol spec. A row that expires early turns verification into a terminal 404. |

The spec's own open question, how PCR0 values are published and pinned by clients and how a
compromised image is revoked, is answered by the signed PCR manifest and rotation runbook in
section 6 below.

## 3. Correctness bugs

| # | Problem | Where | Fix |
|---|---|---|---|
| B1 | The signing key registers once at host boot. If the enclave restarts alone, the new boot's key is never registered, `/ready` stays green, and every statement fails registry lookup with a terminal 404. | `key_registry/registration.rs`, `routes/readiness.rs` | Readiness compares the enclave's current attested signing key against the registered one, re-registers on change and retires the old row. Or the host exits on identity change so the pod restarts as a unit. Check how the chart's sidecar restart interacts with the host container. |
| B2 | Face inference runs synchronously inside the async handler. Two concurrent matches on a 2 vCPU enclave block every tokio worker, including health. | `enclave/src/routes/matches.rs` | `spawn_blocking` behind a semaphore sized to enclave vCPUs, plus a per-request deadline inside the enclave. Pairs with the 429 work in B7. |
| B3 | No explicit input bounds. Image sizes and dimensions are unchecked before decode; the only cap is axum's implicit 2 MiB default, which is smaller than two images plus overhead and will reject valid requests. | `protocol/messages.rs`, `enclave/face_engine.rs`, host router | Explicit `DefaultBodyLimit` sized deliberately. In the enclave, cap image byte length and pixel dimensions before `decode()`. |
| B4 | `match_threshold` is requester-supplied with no floor. Spec calls it `match_min_threshold` and §7.2 has the enclave applying pairwise gates. | `enclave/routes/matches.rs` | Enclave enforces a configured minimum. Feeds the `POST /internal/config` route in section 5. |
| B5 | Retirement is read-modify-write and can lose a concurrent revocation. Noted in the code. | `registration.rs` | Conditional `PutItem` on `status = active`. |
| B6 | Dev runs the host as root and privileged. The Dockerfile sets nonroot, and the sidecar already proves vsock works unprivileged with `seccompProfile: Unconfined`. | deploy values | Nonroot, unprivileged, custom seccomp allowing `AF_VSOCK`. |
| B7 | No capacity limit or load shedding anywhere. Spec requires `429 + Retry-After` on both public routes, and makes rejection the load-shedding mechanism (§6, §8). | host router | Concurrency limit tied to enclave capacity, `429` with `Retry-After` on both routes, request timeout layer. |

## 4. Enclave workload

| Item | Notes |
|---|---|
| Model and pipeline injection (§4, #47) | Largest item. Spec gives the shape: bundle in S3, host fetches, streams over vsock, enclave verifies file hashes against the manifest, loads ONNX, atomically swaps. Reopen the signing question per D5. Sandbox the pipeline in a child process (#41). Until this lands, every model change rotates PCR0 and every client allow-list. |
| PAD and quality checks (§7.2, #48) | Spec puts these in the enclave flow before embedding generation. In progress. Rotates PCR. |
| Face Engine parity (PR #49) | Aligns preprocessing with iOS, pins face-engine 2.16.1. Rotates PCR. Land before any measurement is registered with clients. |
| Enclave logs and metrics | In non-debug mode there is no console and Pontifex has no log transport, so enclave logs vanish. Spec §7.2 mentions a debug report carrying no biometric data returned alongside the response. Build a vsock log and metrics path. Nothing sensitive crosses: no scores, hashes or image bytes. |
| Resource sizing | Dev is 2 vCPU and 1 GiB against a node allocator of 4 CPU and 4 GiB. Load test three ONNX inferences per match on real Nitro hardware, then fix vCPU, memory and concurrency. |
| Advisories | `cargo deny check advisories` is non-blocking because of RUSTSEC-2021-0127 via the Pontifex NSM chain. Track upstream and make it blocking. |

## 5. Host and API

| Item | Notes |
|---|---|
| Enclave affinity (§8, #35) | Spec settles the mechanism: ALB application-controlled stickiness. Assignment arrives without a cookie, the ALB round-robins, the host returns its local enclave's attestation and sets the cookie, and the match follows it back. Needs the cookie in the host, ALB stickiness configured through the Gateway API, and roughly 30s deregistration delay. Verify the cookie survives Cloudflare. Blocks running more than one replica. |
| Capacity and drain (§8) | See B7. Rejection is the load-shedding design, so there is no shared load view to build. |
| `POST /internal/models/activate` | Bundle activation with instant rollback, logged and frequency-bounded. Depends on §4. |
| `POST /internal/config` | Hot-push thresholds and acceptable-PCR sets. Carries B4's floor. Needs an auth story: these are operator routes and must not be internet-reachable. |
| Boot sequence (§7.1) | Readiness goes green only after keys, models and config are all in place. Today it is keys plus enclave health. Extend once §4 lands. |
| Registry revocation | No code path sets `revoked`. Add an operator tool with a conditional write, plus bulk revoke by `pcr0` for a withdrawn image, which needs a GSI on `pcr0`. |
| `key_attestation` on the match response | Code TODO asks whether to drop it now the registry exists. Spec §6 keeps it in the 200 response. Keep it and delete the TODO. |
| Auth | Spec has the host performing no identity checks on the match path. So abuse control is capacity shedding plus edge rate limiting rather than authentication. Confirm that is intended for a route costing three inferences. |
| Metrics (#36) | Traces only today. Add per-route RED metrics, enclave call latency, registry and fetch latency and errors, 409 and 429 rates, readiness state. |
| Shutdown | Retire budget is 5s. Set `terminationGracePeriodSeconds` and a `preStop` drain to match the ALB deregistration delay. |
| Client registry lookup | Uncommitted work in `~/work/embedding-verifier` adds signing-key lookup to `deepface-client`. Finish and land. |

## 6. Build, release cycle and EIF management

### Today

`embedding-verifier` CI publishes host images to GHCR, rebuilds both EIFs on relevant PRs, and
fails when `measurements.json` is stale. `embedding-verifier-deploy` rebuilds host and EIF from
any ref, tags `dev-<sha>-<sha>`, pushes to ECR and deploys to tee-dev.

The gap: the deploy uploads measured PCRs as a workflow artifact and then never uses them.
`ENCLAVE_PCR0` is hardcoded to 96 zeros with `ALLOW_DEBUG_MEASUREMENTS=true`, and the enclave
boots with `ENCLAVE_DEBUG_MODE=true`. The EIF exists only inside the carrier image and is not
published anywhere a client could measure it.

### Target release cycle

1. **Tag** `vX.Y.Z`. Any enclave-reachable change bumps the version in
   `deepface/enclave/Cargo.toml`, which is measured.
2. **Tag pipeline** builds the host image once, builds the EIF with Nix, asserts the measured
   PCRs equal `measurements.json`, builds the carrier image, and publishes a GitHub Release
   carrying the EIF, `pcr.json`, `measurements.json` and the layer-hash closure.
3. **Attest and sign**: build provenance on the EIF and carrier image, and a signed PCR
   manifest. This is the spec's open question about publishing and pinning measurements.
4. **Independent reproduction**: a second runner class rebuilds the tagged EIF and must match
   before the release is deployable.
5. **Deploy consumes tags**: PCR0 is read from the release manifest into `ENCLAVE_PCR0`, never
   hand-typed. A release whose manifest signature fails to verify is refused.
6. **Environments**: dev tracks `main`, stage takes tags with one approver, prod takes tags with
   two and a change window. Add `stage` and `prod` to the deploy repo.
7. **PCR rotation runbook**: publish new PCRs alongside old, deploy, wait for client adoption,
   retire the old measurement. Registry rows carry `pcr0`, so a withdrawn image can be revoked
   in bulk.
8. **Debug-mode gate**: any non-dev deploy fails when `ENCLAVE_DEBUG_MODE` or
   `ALLOW_DEBUG_MEASUREMENTS` is set. The host already asserts this under `APP_ENV=production`.
9. **Model bundles** get their own signed, versioned release track once §4 lands, decoupled
   from PCR rotation.

### Cleanups

Converge CI credentials on the GitHub App and drop the deploy repo's PAT. Delete the sandbox
workflow and close draft PR #3, which targets the old layout. Remove the dead
`deepface-enclave` token step in `build-docker.yml`. The deploy values still default the sidecar
to a GHCR enclave image that is no longer published.

## 7. Infrastructure

Today: one environment, tee-dev in eu-central-1. EKS with an enclave node track
(`m7a.2xlarge`, one ASG per AZ, allocator 4 CPU / 4 GiB), Nitro device plugin, Gateway API to
an external ALB behind Cloudflare with a WAF skip on `POST /v1/matches`, DynamoDB registry
(on-demand, TTL, CMK), an S3 challenge bucket readable anonymously from inside the VPC only,
and pod identity scoped to `GetItem`/`PutItem` plus KMS. A stale crypto-dev identity also
exists.

| Area | Work |
|---|---|
| Environments | Terraform for `tee/stage` and `tee/prod`, own accounts and domains. Remove or document the crypto-dev leftover. |
| ALB stickiness | Application-controlled stickiness and a ~30s deregistration delay, expressed through the Gateway API. Prerequisite for affinity. |
| Capacity | Enclaves per node and replica count from the load test. CPU-based HPA cannot see enclave load, so scale on latency or rejection rate. |
| Availability | PodDisruptionBudget, topology spread, and shared fate between host and sidecar. |
| Network | NetworkPolicy: ingress from the gateway only, egress to S3 and DynamoDB VPC endpoints and Datadog. The endpoints must exist for the bucket policy's `aws:SourceVpc` condition to hold. |
| S3 model bundles | New bucket, versioned, long-lived, with read access for the host identity. Depends on §4. |
| DynamoDB | Point-in-time recovery, deletion protection, throttle alarms, GSI on `pcr0`. |
| Edge | Prod hostname, WAF skip for `/v1/matches`, rate limiting, bot management. Internal routes must not be routable from the internet. |
| IAM | `UpdateItem` for the revocation path only. Host stays `GetItem`/`PutItem`. |

## 8. Operations before go-live

Runbooks for enclave crash loop, stale-attestation exit, registry outage, PCR mismatch on
deploy, key revocation, PCR and model rotation, challenge bucket outage, and compromised image.
Monitors and SLOs on match availability and p95, 409 and 429 rates, 502 fetch failures,
registry errors, readiness flaps, enclave restarts and attestation age. Load and soak on Nitro
hardware, plus chaos tests that kill the enclave, the host and the registry. External security
review of the HPKE channel, the Nitro verifier, the token format and the host/enclave boundary.
Privacy review and DPIA if required. On-call ownership.

## 9. Sequencing

| Phase | Content | Exit criterion |
|---|---|---|
| 0. Make dev real | Wire measured PCR0 from the build into the deploy, turn off debug mode, fix B1 and B6. | Dev runs a measured enclave with attestation actually verified, and survives an enclave-only restart. |
| 1. Deployable topology | Affinity (§8, #35), capacity and 429 (B7), B2, B3, host metrics, enclave log path. | Two or more replicas serve correctly under load, with saturation shedding rather than timing out. |
| 2. Settle the contract | D1 to D4 and D6 decided and implemented. Tag release pipeline, signed PCR manifest, stage environment. | The spec and the code agree, and a tagged release deploys to stage with no hand-typed values. |
| 3. Harden | §4 model injection with #41 sandboxing, #48 PAD, internal routes, B4, protocol ratification, external review. | A model updates without a PCR rotation. Review findings closed. |
| 4. Launch | Prod environment, runbooks, SLOs, pen test, PCR overlap rollout with World App. | Prod serving behind two-approver deploys. |

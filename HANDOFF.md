# Embedding Verifier Handoff

This branch is a playground for building the Face Verifier described in the draft WDP83
specification. It starts from the minimal Rust foundation on `takis/initial-rust-workspace`.

## Primary context

- Product and architecture spec: [draft WDP83: Face verifier](https://app.notion.com/p/worldcoin/draft-WDP83-Face-verifier-3958614bdf8c803ab9a4f0deef8fabd5)
- Clean Rust service and TEE precedent: `~/Repos/world-chat-backend`
- Deployment precedent: `~/Repos/world-chat-backend-deploy`
- Previous face-engine, PCP, Orb-attestation, and Nitro logic: `~/Repos/df-enclave`

The Notion document is a draft. Re-read it before implementing protocol-sensitive behavior;
do not treat claim assignments, routing, chain policy, or all flow decisions as final.

## Current repository state

The workspace intentionally contains only:

- `api`: Axum service with `/health`, a thin `main`, `server.rs`, route modules, and typed
  environment state.
- `secure-enclave`: minimal placeholder process.
- Shared Cargo, Rust, formatting, dependency-policy, and CI configuration.

Keep the API structure aligned with `world-chat-backend`: thin binaries, explicit server
lifecycle, route modules, and dependencies passed through application state.

## Architecture boundaries

- The host is untrusted. It routes, caches, and stores ciphertext but does not decrypt images or
  decide whether faces match.
- Decryption, PCP verification, face-engine execution, threshold decisions, and statement signing
  happen inside the enclave.
- Transit and signing keys are ephemeral and generated inside the enclave. Do not persist, seal,
  export, or share their secret material.
- Models are injected at runtime. Model bytes are not part of the enclave image or PCRs.
- Successful matches return signed, self-describing statements. Failures are structured and
  unsigned.
- Matching is synchronous with bounded concurrency and backpressure, not an unbounded job queue.

Borrow the modular boundaries from World Chat, but do not copy its runtime KMS or peer key-sharing
assumptions. Borrow verified PCP, face-engine, RNG, and attestation logic from `df-enclave`, but do
not preserve its global-state or old API shape automatically.

## Review and PR rules

Review speed is the main constraint. Plan vertically around one endpoint, not horizontally around
layers.

An API endpoint PR should contain:

- One route and its DTOs.
- The service method needed by that route.
- Only the storage operations required by that endpoint.
- Focused route, service, and storage tests.

An enclave endpoint PR should contain:

- One Pontifex request/response operation.
- One handler.
- Only the enclave state, cryptography, or face-engine behavior needed by that operation.
- Focused handler tests.

Prefer 150-350 hand-reviewed lines and treat 400 as a useful stop sign. Exclude `Cargo.lock`,
generated fixtures, and snapshots from the reviewable-LOC count. Do not create preparatory PRs for
types, traits, service layers, or storage layers unless the next endpoint cannot reasonably contain
them. Do not pad naturally small changes.

Limit a live stack to two or three PRs, merge it, and then start the next stack. Each PR description
should state its dependency, reviewable LOC, introduced contract, deliberately deferred behavior,
and verification evidence.

## Recommended immediate work

### Stack 1: prove Pontifex works

1. Secure-enclave Pontifex setup with one `Health` request/response.
   - Add only the minimal shared wire types required by this operation.
   - Add the listener, handler, and a focused dispatch test.
   - Do not add NSM, keys, models, generic RPC abstractions, or unrelated endpoints.
2. API `/readyz`.
   - Call the enclave `Health` operation.
   - Include the route, small client/service code, state wiring, and tests in this PR.
   - Keep `/health` as the process-liveness endpoint.

Merge this stack before starting the next one.

### Stack 2: transit key

1. Enclave `GetTransitKey` operation.
   - Generate an ephemeral X25519 key at boot.
   - Bind the public key into an NSM attestation document.
   - Return the attestation through one Pontifex operation.
2. API `GET /v1/enclave/transit-key`.
   - Include route, service, enclave call, response mapping, and tests.
   - Do not add host caching in the first version unless measurements show it is necessary.

Merge this stack before planning signing identity or model activation in detail.

## Endpoint order after the first two stacks

Use the same two-PR pattern where an operation crosses the host/enclave boundary:

1. Enclave `GetSigningIdentity`.
2. API `GET /.well-known/face-verifier.json`, including only the key-registry storage it needs.
3. Enclave `ActivateModel`.
4. API `POST /internal/models/activate`, including S3 retrieval.
5. Enclave `Match2Way`.
6. API `POST /v1/matches`, initially supporting only 2-way matching.
7. API `POST /v1/challenges`, including its DynamoDB record and S3 ciphertext write.
8. API `GET /v1/challenges/{id}`.
9. Enclave `Match3Way`, then extend the existing matches route with that request variant.
10. Enclave `MatchChained`, then extend the existing matches route with that request variant.
11. API `POST /internal/config` and its corresponding enclave configuration operation.

If `Match2Way` cannot stay below roughly 400 reviewable lines, split it into at most two executable
increments: request/decryption/PCP verification, followed by face comparison and signed output.
Avoid a long chain of independent crypto, type, and service-layer PRs.

## Useful reference locations

In `world-chat-backend`:

- `backend/src/server.rs`: dependency wiring and server lifecycle.
- `backend/src/routes/`: route organization.
- `secure-enclave/src/state.rs`: enclave-held state and NSM initialization precedent.
- `secure-enclave/src/pontifex_server/`: Pontifex handler organization.
- `shared/attestation-verifier/`: Nitro attestation parsing and verification.

In `df-enclave`:

- `enclave/src/main.rs`: Pontifex listener, NSM RNG guard, and request dispatch.
- `enclave/src/keys.rs`: ephemeral encryption and signing key precedent.
- `enclave/src/face_engine.rs`: face-engine adapter and error conversion.
- `common/src/pcp.rs`: Orb key attestation and PCP signature verification.
- `common/src/types.rs`: old wire types and structured face-engine errors.

In `world-chat-backend-deploy`:

- `.github/workflows/build-and-deploy-secure-enclave-v2.yaml`: source image, EIF build,
  measurements, staging, and production separation.
- `builder/`: Nitro host startup, vsock proxying, initialization, and cleanup.
- `deploy/values-world-chat-secure-enclave-v2-stage.yaml`: Nitro resources and probes.

## Decisions that should remain explicit

Do not silently decide these while implementing an unrelated endpoint:

- Single-frame liveness versus burst/video input.
- Orb attestation service lookup versus PoH Credential anchoring.
- Final signed-statement claims, integer keys, domain separator, and WIP-106 compatibility.
- Synchronous latency and challenge-expiry expectations.
- Multi-enclave gateway routing versus host-mesh rerouting.
- Whether chained matches can anchor any committed image or only the RP challenge image.
- Build-time EIF signing/provenance policy and how public `.eif` and `pcrs.json` artifacts are
  published.

## Verification baseline

Run the relevant focused tests for every PR, followed by the workspace checks before publishing:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features --
cargo test --locked --all
cargo build --locked --release
cargo deny check
```

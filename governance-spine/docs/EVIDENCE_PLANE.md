# GovSec Evidence Plane v1

GovSec Evidence Plane records cryptographically verifiable evidence about governed execution. It does not authorize an action and it does not replace the capability path.

The runtime decision remains authoritative. Evidence is produced from the result returned by the governed pipeline.

## Security properties

Each evidence event carries:

- an evidence schema version;
- an explicit evidence epoch identifier;
- a monotonic sequence number within the epoch;
- the hash of the immediately preceding event or the signed parent checkpoint head;
- an event hash covering the bounded evidence payload and chain metadata;
- the runtime signing public key and fingerprint;
- an Ed25519 signature over the event hash.

`EvidencePlane::verify_snapshot` detects mutation, interior deletion, reordering, chain-parent substitution, mixed epochs, mixed signers, invalid sequence values, and invalid signatures. `verify_snapshot_against_checkpoint` additionally detects tail truncation against a signed checkpoint.

The evidence payload intentionally excludes raw prompts, model outputs, tool arguments, credentials, and raw resource locators. Resource locators are represented by SHA-256 digests.

## Epochs and restart continuity

Evidence continuity across process restarts is explicit rather than implied.

`EvidencePlane::checkpoint` produces a signed checkpoint containing the current epoch, sequence, and chain head. `EvidencePlane::from_checkpoint` verifies that checkpoint against the configured runtime signing identity and starts a new epoch whose parent is the prior signed head.

If no checkpoint is supplied, the runtime starts a new independently identifiable epoch. It does not claim continuity with an earlier process.

Persisting the checkpoint is a deployment responsibility. The planned external WORM sink is the long-term persistence boundary; it is intentionally not implemented by this first Rust core.

## Sink model

`EvidenceSink` is an append-only export contract. The in-process evidence chain is committed first. If an external sink is unavailable, the event remains in the local evidence plane and is queued for ordered retry. A sink failure never fabricates an authorization result.

The first external production sink is planned as an AWS write-only evidence path backed by KMS and S3 Object Lock. That infrastructure is separate from this core implementation.

## Governed pipeline decorator

`EvidenceGovernedPipeline` wraps `GovernancePipeline` without moving policy or authorization logic into the evidence layer.

It currently records:

- context approval or refusal;
- provider capability authorization or refusal;
- action capability authorization or refusal;
- capability consumption;
- capability rejection, including replay and binding mismatch outcomes returned by the existing capability verifier.

The decorator uses the same `Arc<CryptoEngine>` supplied to `GovernancePipeline`, so evidence signatures and existing runtime audit signatures share the configured runtime signing identity.

## Integration boundary

The `governance_spine_server` runtime is wired through `EvidenceGovernedPipeline`. Its authenticated `GET /evidence` endpoint exports the bounded evidence records needed by a private adapter or evidence collector without exposing raw tool arguments or resource locators.

This module is the GovSec-side evidence core. Product adapters and agent frameworks should consume GovSec decisions and evidence receipts; they must not recreate the decision logic themselves.

The governed OpenClaw mapping is deliberately a subsequent integration step. That mapping should route the existing context/action/provider gate calls through `EvidenceGovernedPipeline` or an equivalent server wiring while preserving the rule:

> The adapter may translate a GovSec decision for display. It may never make one.

## Verification

Run:

```text
cd governance-spine
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

Evidence-plane tests cover chain verification, signature verification, mutation detection, deletion/reordering detection, signed checkpoint continuity, external sink failure/retry behavior, and an end-to-end context -> action authorization -> consume -> replay evidence sequence.

## Scope

Evidence Plane v1 is an implementation feature, not a compliance certification. External immutable retention, deployment-specific pseudonymization policy, retention periods, key-management controls, and WORM storage configuration remain deployment responsibilities until the AWS evidence sink is provisioned and verified.

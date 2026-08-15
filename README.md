# GovSec

**Agent execution governance from LOGOS Governance Systems, Inc.**

GovSec is a governance runtime positioned between agent reasoning and consequential execution.

It does not govern what an AI is allowed to think. It governs what an agent is allowed to execute.

GovSec evaluates governed context and proposed execution, derives authorization-relevant facts at the trusted boundary, binds authority to canonical execution state, and issues narrowly scoped capabilities that can be consumed only under the conditions for which they were authorized.

## Core enforcement model

GovSec binds execution authority to specific runtime facts including principal, session, run, model, tool, resource, invocation, context, action, and active policy state.

The current action-capability path is single-use.

A consequential action follows this sequence:

    governed context
          |
          v
    model / reasoning
          |
          v
    proposed action
          |
          v
    GovSec authorization
          |
          v
    bound execution capability
          |
          v
    exact tool/resource execution
          |
          v
    capability consumed

Changing a bound field after issuance does not expand authority. It invalidates verification.

## Repository

    GovSec/
    ├── governance-spine/     Rust governance runtime and tests
    ├── evidence/             Frozen runtime evidence
    ├── README.md
    ├── SECURITY.md
    ├── LIMITATIONS.md
    ├── PRIVACY.md
    ├── PROVENANCE.md
    └── LICENSE

The repository intentionally excludes unrelated agent frameworks, model runtimes, product-specific orchestration, DEP.KEYSTONE, and historical LOGOS ASF assets.

## Runtime

`governance-spine/` contains the Rust enforcement runtime, including:

- canonical model-context and action envelopes;
- SHA-256 context and action binding;
- signed execution capabilities;
- single-use capability consumption on the current action path;
- session, run, principal, provider, model, tool, resource, and invocation binding;
- signed-constitution verification before server startup;
- default denial for unknown action classes;
- persistent audit signing identity support;
- session-level accumulated governance state;
- real HTTP enforcement endpoints and loopback tests.

## Evidence Plane

`governance-spine/src/evidence.rs` provides the GovSec Evidence Plane v1 core. It records bounded execution evidence without moving authorization logic into the evidence layer.

Evidence events are append-only, hash-linked, Ed25519-signed, and grouped into explicit epochs. Signed checkpoints verify the expected head and sequence (including tail-truncation detection) and can link a new runtime epoch to the prior evidence head after restart; without a checkpoint, the runtime starts a visibly separate epoch rather than claiming continuity it cannot prove.

The evidence payload excludes raw prompts, model outputs, tool arguments, credentials, and raw resource locators. Resource locators are represented by SHA-256 digests.

`EvidenceGovernedPipeline` records context decisions, provider/action authorization decisions, and capability consumption or rejection while the underlying `GovernancePipeline` remains the sole authority. The HTTP server is wired through this decorator and exposes an authenticated `GET /evidence` export surface for bounded evidence records. External sinks implement the `EvidenceSink` contract; sink outages retain local evidence and queue ordered retry.

The AWS WORM sink and governed OpenClaw mapping are separate deployment/integration steps. See `governance-spine/docs/EVIDENCE_PLANE.md`.

## Verification

    cd governance-spine
    cargo test --all-targets
    cargo clippy --all-targets -- -D warnings

## Live evidence

Frozen evidence from the canonical GovSec runtime is under:

    evidence/capability-lab/

The current evidence freeze demonstrates, against synthetic resources:

    CAPABILITY_CONSUMED
    CAPABILITY_REPLAY_REJECTED
    CAPABILITY_RESOURCE_MISMATCH
    CAPABILITY_TOOL_MISMATCH
    CAPABILITY_RUN_MISMATCH

Each freeze includes a manifest, raw runtime request/response artifacts, the signed demo profile, startup evidence, and SHA-256 checksums.

The evidence represents real GovSec runtime decisions. The resources used in the demonstration are synthetic.

## Integration principle

The component requesting execution must not also be able to manufacture the facts used to authorize that execution.

GovSec is intended to be inserted at the boundary where agent output becomes provider execution, tool execution, data access, infrastructure mutation, external communication, or another consequential side effect.

## Status

GovSec is under active development and evaluation.

This repository is not a compliance certification, legal determination, warranty of security, or representation that every possible agent integration is governed correctly. See `LIMITATIONS.md`.

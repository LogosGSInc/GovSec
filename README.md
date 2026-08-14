# GovSec

GovSec is an AI governance runtime and reference implementation from LOGOS Governance Systems, Inc. It evaluates model context and proposed actions before execution, binds decisions to canonical hashes, issues narrowly scoped capabilities, and rejects mutation, rebinding, replay, and unknown action classes by default.

This private repository is the canonical GovSec development baseline. Product-specific adapters and complete third-party runtimes are maintained separately.

## Repository contents

- `governance-spine/` — Rust governance runtime, envelope contracts, capability enforcement, constitution verification, GovMem integration, and tests.
- `govmem-tools/` — GovMem record, delta, promotion, and loading utilities.
- `keystone/` — DEP.KEYSTONE build-trust and software-composition tooling.
- `integrations/dep-keystone/` — DEP.KEYSTONE-to-GovSec ingress boundary.
- `docs/` and `proofs/` — architecture and verification summaries.

## Enforced runtime boundaries

The current governance spine provides:

- canonical `logos.model-context.v1` and `logos.action.v1` envelopes;
- SHA-256 context and action bindings;
- signed, single-use capabilities;
- provider, model, run, principal, resource, and tool-call binding;
- default denial for unknown tools and dangerous arguments;
- signed-constitution verification at server startup;
- replay and cross-plane substitution rejection;
- cryptographically signed, tamper-evident audit-chain entries;
- session-governance enforcement through GovMem.

See `governance-spine/docs/ENVELOPE_CONTRACTS.md`.

## Verification

```bash
cd governance-spine
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

```bash
python3 -m pytest keystone/tests
```

The imported source baseline passed 204 Rust tests, including compiled-server loopback, control-plane, envelope, replay, mutation, and golden-hash parity tests. Re-run verification in every clone and release environment.

## Runtime requirements

The server verifies a signed constitution using its trusted public key. Constitution signing occurs offline; the server does not require the constitution-authority private key.

Runtime configuration includes `SENTINEL_SERVICE_TOKEN`, `SENTINEL_OPERATOR_RESET_TOKEN`, `SENTOW_CONSTITUTION_PATH`, `SENTOW_CONSTITUTION_SIGNATURE_PATH`, `SENTOW_AUDIT_KEY_PATH`, and `SENTOW_BIND`.

The checked-in constitution is a placeholder verification artifact—not an approved production policy.

## Status

GovSec is under active private development and evaluation. It is not a compliance certification, legal determination, warranty of security, or authorization for unattended production deployment.

Review `LIMITATIONS.md`, `SECURITY.md`, `PRIVACY.md`, and `PROVENANCE.md` before evaluation.

## OpenClaw compatibility

GovSec has been exercised through a separately maintained governed OpenClaw integration. This repository retains the GovSec-side contracts and tested control-plane semantics, but it does not include or redistribute the OpenClaw runtime or integration overlay.

LOGOS Governance Systems, Inc. is not affiliated with or endorsed by OpenClaw.


# DEP.KEYSTONE Ingress — Trust Boundary Audit

**Status:** Audit only. No code changes. No trust root, verifier, or evidence
type has been implemented.
**Scope:** `integrations/dep-keystone/` (preserved reference copy in this
worktree).
**Conclusion:** DEP.KEYSTONE ingress evidence cannot yet be elevated into
GovSec execution authority. The preserved module has no cryptographic
verification of any kind. Building a "signed/verified ingress evidence
contract" now would mean inventing a trust root that does not exist anywhere
in the preserved artifacts, which is a security-architecture decision this
audit deliberately does not make.

---

## 1. What was audited

Three files, preserved read-only in this worktree at
`integrations/dep-keystone/`:

- `dep_keystone_ingress.py` (363 lines) — the actual gate logic.
- `DEP_KEYSTONE_TRAINING_INGRESS.schema.json` (236 lines) — the ingress
  record schema.
- `TR_04D_DEP_KEYSTONE_GOVSEC_INGRESS_ALIGNMENT.md` (216 lines) — the design
  doc for this module.

## 2. What the module actually is

`dep_keystone_ingress.py` is an **Abigail-side training-data admissibility
gate**. Its own header and design doc are explicit about this:

- It lives at `training/dep_keystone_ingress.py` in the Abigail tree (not in
  `governance-spine`).
- Its job is to decide whether an artifact (training data, an embedding
  source, a model dependency) may proceed into Abigail's **training**
  pipeline — a distinct lifecycle from `governance-spine`'s **runtime
  request/response governance** (Arbiter → HAAP → capability-execution
  chain).
- Per its own design doc: "TR-04D is optional at individual pipeline stages.
  Hard mandatory enforcement at source registry level is a future
  migration," and "Source Registry clearance and Clearance Ledger approval
  are independent Abigail-side gates — they are not replaced by DEP.KEYSTONE
  evidence."

**It is not currently a runtime GovSec decision input.** Nothing in
`governance-spine` calls it, imports it, or depends on it, and nothing in
this audit changes that.

## 3. What the module actually verifies (and doesn't)

`load_ingress_record()` is:

```python
return json.loads(p.read_text(encoding="utf-8"))
```

That is the entire trust mechanism. `validate_ingress_record()` and
`assert_training_ingress_allowed()` then branch on the dict's own
self-reported fields — `dep_keystone_status`, `dep_keystone_trust_score`,
`govsec_admissibility_status`, evidence-ref strings, `artifact_sha256` — with
no step anywhere that cryptographically verifies those fields were actually
produced by the real DEP.KEYSTONE tool, or by any specific authority at all.

A full grep of the schema (`DEP_KEYSTONE_TRAINING_INGRESS.schema.json`) for
`signature`, `signed`, `public_key`, `hmac`, and `ed25519` returns no matches.
The evidence-ref fields (`dep_keystone_verification_report_ref`,
`dep_keystone_evidence_sha256_ref`, `dep_keystone_sbom_ref`,
`dep_keystone_trust_cert_ref`) are plain strings — references to files that
are assumed to exist and be trustworthy, never opened, hashed, or
signature-checked by this module itself.

Concretely, the schema and gate logic are **missing every one of the
following**, all of which a real "signed/verified ingress evidence contract"
would require:

- signer identity / signing authority
- signature algorithm and canonical serialization (what bytes are signed)
- a trusted public key (or key set) and a rotation/distribution mechanism
- a certificate chain or equivalent authority binding
- an HMAC or nonce for replay protection
- `issued_at` / `expires_at` semantics
- revocation handling
- a documented fail-closed behavior when verification is unavailable

This is the same category of gap the rest of this codebase treats with real
weight elsewhere — see `governance-spine/src/constitution.rs`'s pinned
trusted signing key and `governance-spine/constitution/README.md`'s offline
key-custody documentation, and the persisted Ed25519 audit-signing identity
wired through `GovernancePipeline`. DEP.KEYSTONE ingress evidence has no
equivalent today.

## 4. Why this audit does not implement a verifier

Inventing a signing scheme, a placeholder trust root, or a Rust type that
*looks* like verified evidence (e.g. a `VerifiedIngressEvidence` struct with
no real signature check behind it) would create exactly the failure mode
this phase exists to prevent: an **implicit trust bypass** — code that
appears to gate on cryptographic evidence but actually gates on unsigned,
self-reported JSON. That is a security-architecture decision (who signs,
what the failure mode is, how keys are custodied) that belongs to the same
deliberate, reviewed process that produced the constitution-signing and
audit-signing key infrastructure already in this repo — not something to
guess at silently in the course of an integration phase.

## 5. Minimum decisions required before any implementation

Before `governance-spine` (or any GovSec-owned adapter) can accept
DEP.KEYSTONE ingress evidence as an input to a real decision, the following
need explicit answers — from the operator/architecture owner, not invented
here:

1. **Signing authority and custody owner** — who (or what system) holds the
   private key that attests DEP.KEYSTONE evidence, and who custodies it.
2. **Signature algorithm and canonical serialization** — e.g. Ed25519 over
   a defined canonical byte form (this repo already has a working pattern
   for this in `crypto.rs`/`constitution.rs`; reuse or diverge deliberately).
3. **Trusted public-key distribution and rotation** — how a verifier obtains
   and pins the correct public key(s), and how rotation is handled without
   breaking already-issued evidence.
4. **Evidence issuer identity** — is the signer DEP.KEYSTONE itself, an
   Abigail-side attestor, or a third party co-signing on its behalf.
5. **Subject/artifact binding** — what exactly the signature covers (must
   bind unambiguously to `artifact_sha256` or equivalent, so evidence for
   one artifact can't be replayed against another).
6. **Evidence version** — a versioned evidence format so verifiers can
   reject or migrate old shapes deliberately, not silently.
7. **`issued_at` / `expires_at` semantics** — how long a piece of evidence
   remains valid, and what happens when it's presented after expiry.
8. **Replay and revocation handling** — can the same evidence be presented
   more than once, and how a compromised or superseded piece of evidence
   gets revoked before its natural expiry.
9. **Required claims and confidence/trust semantics** — which fields are
   mandatory, and how a trust score (like `dep_keystone_trust_score`) maps
   to a pass/fail/escalate decision, defined precisely rather than by
   convention.
10. **Fail-closed behavior** — what happens when evidence is missing,
    malformed, unverifiable, or the verifier itself is unavailable; the
    default must be to deny, matching this codebase's existing posture
    (missing/invalid constitution keys, audit keys, and operator-reset
    tokens all fail closed today).
11. **Which GovSec action classes require this evidence** — evidence
    requirements should be scoped to specific `action_class` values in the
    Phase 2D capability chain (`governance-spine/src/capability.rs`), not
    applied blanket across all governed actions.
12. **Advisory vs. blocking vs. multi-source** — whether DEP.KEYSTONE
    evidence alone can block/allow a decision, or whether it is one signal
    among several that a policy evaluation combines — this determines
    whether a single unsigned/forged record could ever be sufficient on its
    own to move a decision.

## 6. Architecture boundary (for when implementation does happen)

- DEP.KEYSTONE may eventually emit signed build-time or artifact-trust
  attestations as a first-class product feature.
- `governance-spine` may eventually verify those attestations through a
  **generic external-attestation interface** — analogous to how Phase 2E's
  `GovMem` refactor (see `GOVSEC_V2_PROJECT_TRACKER.md`) made policy-profile
  selection generic rather than baking in Abigail's department table:
  evidence verification should be a generic contract GovSec defines, with
  DEP.KEYSTONE as one possible (signed) evidence producer among others.
- The existing Abigail Python gate (`dep_keystone_ingress.py`) remains
  separate and **must not be treated as a cryptographic trust authority** —
  it performs training-pipeline admissibility bookkeeping over
  self-reported fields, which is a legitimate and useful thing for it to do
  in its own domain, but is not equivalent to verified evidence.
- No evidence, once a real verification scheme exists, may authorize
  provider execution directly. At most it becomes one input to a final
  governed decision (Phase 2D's `authorize_provider_execution` /
  `DecisionRequest`), after verification and policy evaluation — never a
  bypass around HAAP, the Arbiter, or the capability chain's existing
  approval path.

## 7. Disposition

Phase 3 is closed as an audit. No `governance-spine` source changed. The
preserved `integrations/dep-keystone/` files are untouched. Implementation
is blocked on the decisions in §5 being made explicitly, likely as their own
follow-up phase once an operator/architecture owner has answered them.

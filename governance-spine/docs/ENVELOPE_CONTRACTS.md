# GovSec canonical envelope contracts

Status: contracts, pipeline admission, and capability wiring are implemented
and tested. OpenClaw-side integration (Phase 2/3 of the reconciliation) is
tracked separately — see the integration evidence report.

## Trust boundary

The external runtime supplies raw model context and a raw tool call. A trusted
adapter must derive the principal, normalized resource, tool name and active
signed-policy identity. Callers must never be allowed to assert those authority
fields directly.

## Model-context envelope

`logos.model-context.v1` binds one model run to:

- principal, session and run identifiers;
- provider and model identifiers;
- signed policy version and policy hash;
- the exact provider-bound context-payload hash;
- the exact assembled system-prompt hash;
- the ordered tool-schema hash;
- the injected workspace/bootstrap manifest hash;
- ordered, source-labelled text segments;
- attachment identifiers, types, sizes and content hashes.

Every segment has a contiguous ordinal. External user content, prior
conversation, tool results, attachments, hook and runtime injections, and
compaction summaries are all explicitly selected for Sentinel inspection on
every run. This prevents model-produced or imported text from bypassing the
ingress scan merely because it appears in history.

`context_hash` is SHA-256 over deterministic canonical JSON excluding the
`context_hash` field itself. Mutation, reordering or rebinding changes the hash.

## Action envelope

`logos.action.v1` binds one proposed tool call to:

- tool name and full JSON arguments;
- normalized resource kind and locator;
- trusted principal, session, run and tool-call identifiers;
- signed policy version and policy hash;
- the approved `context_hash` that caused the action;
- a deterministic `action_hash` excluding only itself.

JSON object keys are sorted before hashing, so semantically identical argument
objects have the same digest regardless of insertion order. Arrays retain order.

The strict baseline classifier:

- denies unknown tools;
- denies path traversal, credential access and protected system writes;
- denies destructive shell, privilege escalation and downloaded-code piping;
- denies browser script evaluation;
- requires explicit authorization for ordinary shell, filesystem mutation and
  browser interaction;
- permits only non-sensitive reads at the contract-classification layer.

This classifier is a minimum fail-closed gate, not the signed constitution. The
constitution can be stricter but cannot turn a structural contract failure into
an approval.

## Limits

- 4,096 context segments;
- 256 KiB per segment;
- 4 MiB total context text;
- 128 attachments;
- 256 KiB canonical action arguments;
- JSON nesting depth of 32.

Missing, malformed, oversized or hash-mismatched envelopes fail closed.

## Contract tests

`tests/envelope_contracts.rs` fixes one golden digest for each schema and tests
mutation, reordering, context rebinding, malformed digests, attachment binding,
unknown tools, destructive shell, downloaded-code piping, protected writes,
credential reads, path traversal and browser script execution.

## Pipeline and capability wiring (implemented)

`GovernancePipeline::inbound_context`/`inbound_context_with_identity`
(`src/pipeline.rs`) is the context-aware sibling of `inbound`/
`inbound_with_identity`: it verifies a `ModelContextEnvelope` structurally,
runs Sentinel over every segment `ContextSource::requires_content_inspection`
selects (not only the newest turn), then runs Corridor/OverWatch/GovMem/HAAP/
OIM over the concatenated inspectable content exactly as the plain-text path
does. On approval it calls `SentinelVerdictLedger::record_final_approved_with_context`,
which is the *only* way a verdict acquires a bound `context_hash`/`run_id` —
the legacy plain-text path (`record_final_approved`) never sets them, so it
can never satisfy a provider or action authorization request.

`GovernancePipeline::authorize_provider_execution` now requires
`context_hash`/`run_id`/`policy_version` on `ProviderAuthorizationRequest` and
rejects (fails closed) unless they match the resolved verdict's bound values.
`GovernancePipeline::authorize_action_execution` resolves the same verdict,
requires a matching `context_hash`, builds and independently seals an
`ActionEnvelope` from server-trusted fields, evaluates it with
`evaluate_strict()`, and denies outright on `ActionDisposition::Deny`.

Both authorities share one generic capability shape in `src/capability.rs`
(`AUTHORITY_PROVIDER_EXECUTE` / `AUTHORITY_ACTION_EXECUTE`). `CapabilityToken`
carries `run_id`, `context_hash`, `policy_version`, `policy_hash`, and —
action-only — `action_hash`, `tool_name`, `resource_kind`, `resource_locator`,
`tool_call_id`. Every one of these fields is part of the signed
`canonical()` string, so a capability is unusable if any of them are tampered
with in storage, and `consume()` compares the *presenter's* claimed values
against the stored, signature-verified token field-by-field before marking it
used exactly once.

HTTP surface (`src/server.rs`): `POST /context/inspect` (submit a
`ModelContextEnvelope`, get back `context_hash`/`run_id`/`verdict_id` on
approval), `POST /provider/authorize` and `POST /provider/consume` (now
require `context_hash`/`run_id` in the request body), `POST /action/authorize`
and `POST /action/consume` (new, mirroring the `/provider/*` pattern rather
than reviving `/openclaw/*`). Trusted fields — `principal_fingerprint`,
`policy_hash`, `policy_version` — are always derived server-side from the
authenticated service token and the running signed configuration; a client
can request evaluation of untrusted facts (tool name, arguments, resource,
context content) but cannot assert authority.

## Remaining hardening unit

Write terminal outcomes to an immutable append-only audit sink. The
`SentinelVerdictLedger`/`CryptoEngine` hash chain here is tamper-evident
(detects retroactive edits) — it is not immutable storage; nothing in this
change claims otherwise. See the integration evidence report's "known
limitations" section.

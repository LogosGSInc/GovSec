# GovMem Store 1 — Per-Agent Scoping

LOGOS Governance Systems Inc. — Architecture Law Document

---

## Architecture Law

> Shared doctrine, isolated learning.
> Shared audit, scoped promotion.
> Shared analysis, gated enforcement.
> Abigail may aggregate; agents may not overwrite each other.

---

## What Store 1 Is

Store 1 is **per-agent operational learning memory**. Each governed agent
(Sentinel, OverWatch, future agents) has its own Store 1 partition. A Store 1
record may affect detection, response shaping, escalation, confidence tuning,
or memory_action behavior — but only for the one agent it is scoped to.

Store 1 records exist only after the full promotion path:

```
TAX2 output
  → Store 2 Loader              (tools/govmem/store2_loader.py)
  → Store 1 Delta Candidate     (tools/govmem/store1_delta.py)
  → Operator Review             (human, with approval manifest)
  → Store 1 Apply Gate          (tools/govmem/store1_apply.py)
  → Per-agent file-backed Store 1 artifact
```

No step may be skipped. No tool writes Store 1 without an operator approval
manifest.

---

## Per-Agent Isolation

**Agents cannot share mutable Store 1 memory directly.**

Every applied record carries:

| Field | Required value |
|---|---|
| `agent_scope` | `agent_local` |
| `shared_with_peer_agents` | `false` |
| `target_agent_id` | exactly one agent, validated as a safe path component |

Isolation is enforced at three levels:

1. **Schema** — `shared_with_peer_agents` is `const: false` in
   `store1_record_schema.json`.
2. **Write gate** — `store1_apply.py` rejects any candidate whose
   `target_agent_id` does not match the `--agent-id` it was invoked with
   (`agent_id_mismatch`), and exits with `SECURITY_VIOLATION` if the agent ID
   contains path traversal or unsafe characters.
3. **Filesystem** — records are written only under
   `<root>/agents/<agent_id>/`, and every output path is verified to resolve
   inside the selected root before anything is written.

---

## Namespace / Path Model

Default root: `/tmp/govmem_store1/` — never the repository, never live memory.

```
<root>/
  agents/
    <agent_id>/
      approved/
        store1_<agent_id>_<run_id>.jsonl     ← applied operational records
      rejected/
        rejected_<agent_id>_<run_id>.jsonl   ← apply-time rejections with reasons
  abigail/
    aggregation/
      abigail_agg_<run_id>.jsonl             ← read-view copies for Abigail
  apply_log/
    apply_log_<run_id>.json                  ← machine-readable audit
    apply_log_<run_id>.md                    ← human-readable audit
```

---

## Store 2 Observes; Store 1 Adapts Only After Approval

- **Store 2** is analysis-only, cross-agent, and never enforces. It may
  recommend Store 1 deltas; it may not apply them.
- **Store 1** changes only when an operator approves a specific candidate by
  `source_record_id` in an approval manifest, and the apply gate's hard rules
  all pass.

The apply gate's write-gate rules (all must hold):

- Candidate is a genuine `store1_delta_candidate` with `candidate_only: true`,
  `store1_write_applied: false`, `promotion_status: candidate_review_required`,
  `operator_approval_required: true`, and `approved_by_operator: false`
  (approval lives in the manifest, never on the candidate).
- `target_agent_id` present, safe, and matching `--agent-id`.
- `shared_with_peer_agents: false`.
- `source_record_id` present and listed in the operator approval manifest with
  a non-empty `approval_id`; the manifest itself carries `approved_by` and
  `approved_at`.
- Output paths resolve under the selected root.

---

## Provenance: What Cannot Become Operational Truth

Only `sentinel_source: "sentinel_overwatch"` may be applied to Store 1.

`heuristic_simulation` and `legacy_no_source` outputs are analysis evidence,
not operational truth:

- Without a manifest approval, such candidates are **softly rejected**
  (`sentinel_source_not_operational`).
- If an approval manifest attempts to approve one, the apply gate treats it as
  a **forged approval**: it prints `SECURITY_VIOLATION`, exits 1, and writes
  nothing. Operator approval cannot override provenance law.

---

## Abigail Aggregation Boundary

Abigail aggregation is a **governed read-view, not a peer mutation path**.

- When an applied record has `shared_with_abigail: true`, the apply gate writes
  a **copy** into `<root>/abigail/aggregation/`. Abigail reads from there only.
- Abigail never reaches into `agents/<agent_id>/` and never writes back into
  any agent namespace.
- Every aggregation copy retains `abigail_training_eligible: false`,
  `abigail_training_requires_approval: true`, and
  `shared_with_peer_agents: false`. Aggregation is visibility, not training.
- Cross-agent doctrine changes Abigail recommends must become repo, taxonomy,
  or policy changes through governance review — never silent shared mutable
  memory.

---

## What This Is Not

- **This file-backed Store 1 path is not live runtime memory.** The Rust
  governance-spine runtime (Tier 1 SessionMemory, Tier 2 StrategicMemory,
  GovMem V2 sessions) is untouched by these tools.
- The runtime's `GovMemSession.agent_id` field exists but is not yet populated
  by any call site. **Rust runtime wiring is deferred to a future correction**
  and will happen only after the file-backed path is proven through
  verification.
- The apply gate does not train Abigail, does not call endpoints, does not
  mutate Sentinel or OverWatch behavior, and does not modify the repository.

---

## Mode Status

- Mode 1 (heuristic/legacy evidence): review-only forever — cannot reach
  Store 1.
- Mode 2 (sentinel_overwatch evidence): may produce candidates and, after
  operator approval, **file-backed** Store 1 records via the apply gate.
  Live runtime adoption of those records remains blocked until the Rust
  runtime correction lands.

# GovMem Store 1 Promotion Gate

LOGOS Governance Systems Inc. — Architecture Law Document

---

## Architecture Law

> Shared doctrine, isolated learning.
> Shared audit, scoped promotion.
> Shared analysis, gated enforcement.
> Abigail may aggregate; agents may not overwrite each other.

---

## Store Roles

### Store 2 — Observes

Store 2 is the analysis-only store. It receives TAX2 govmem_ingest output via the Store 2 Loader (`tools/govmem/store2_loader.py`) and produces structured analysis artifacts.

Store 2 records are **never applied to runtime behavior**. Every record carries hard invariants enforced by the loader and verified by this tool:

- `enforcement_allowed: false`
- `store1_write_allowed: false`
- `abigail_training_allowed: false`

Store 2 exists to make observations visible for review, not to act on them.

### Store 1 — Adapts Only After Approval

Store 1 holds operational per-agent memory. It governs how an agent's sentinel and memory subsystems behave at runtime.

Store 1 is updated **only** through an explicit, operator-approved promotion path. No automated tool, no TAX2 run, no Store 2 loader run, and no Store 1 delta candidate generator may write to Store 1 directly.

---

## Agent Isolation

**Agents cannot overwrite each other's Store 1.**

Each Store 1 delta candidate is scoped to a single `target_agent_id`. The `agent_scope` field is always `agent_local`. The `shared_with_peer_agents` field is always `false`.

This isolation is architectural, not configurable. A candidate generated for agent `sentinel` cannot be applied to agent `overwatch`, even by an operator acting in good faith. Candidates must be generated per-agent.

---

## Abigail's Role

Abigail may **aggregate** across agents for cross-agent analysis.

Abigail may **not** be trained from Store 1 delta candidates without explicit operator approval. The following invariants hold at candidate generation time:

- `abigail_training_eligible: false`
- `abigail_training_requires_approval: true`

Abigail training from any Store 1 delta requires a separate governed promotion path. The candidate generator does not initiate it.

---

## Mode 1 vs. Mode 2 Output

### Mode 1 — Review Only

Mode 1 TAX2 outputs are sourced from `heuristic_simulation` or `legacy_no_source`. These outputs:

- Are loaded into Store 2 with `promotion_status: analysis_only`
- Generate Store 1 delta candidates with `finding_type` of `simulation_evidence_only` or `legacy_analysis_only`
- Receive `recommended_store1_action: review_only_no_promotion`
- **Must not recommend any operational Store 1 action**
- Yield a safety verdict of `REVIEW_ONLY_NO_PROMOTION`

Mode 1 candidates exist to surface patterns for human review. They do not support promotion.

### Mode 2 — Candidate Generation

Mode 2 TAX2 outputs are sourced from `sentinel_overwatch`. These outputs:

- Are loaded into Store 2 with `promotion_status: review_required` or `denied`
- May generate Store 1 delta candidates with operational `finding_type` values
- Receive action recommendations commensurate with their level (A–D):
  - Level D: `candidate_deny_promotion_rule` / `block_and_escalate`
  - Level C: `candidate_quarantine_rule` / `quarantine`
  - Level A/B: `candidate_observation_rule` / `flag`
- Yield a safety verdict of `CANDIDATES_ONLY_CONFIRMED`

Mode 2 candidates are **not applied deltas**. They are proposals for operator review only.

**Mode 2 remains blocked until the Store 1 promotion boundary is fully operational.**

---

## Approval Path

The only authorized path from TAX2 output to a Store 1 change is:

```
TAX2 output
  → Store 2 Loader  (tools/govmem/store2_loader.py)
        produces Store 2 analysis artifacts only
        no enforcement, no Store 1 writes, no Abigail training

  → Store 1 Delta Candidate Generator  (tools/govmem/store1_delta.py)
        produces candidate files for review
        no writes to Store 1, no writes to live memory
        no endpoint calls

  → Operator Review
        human operator reads candidate JSONL and promotion_review report
        evaluates finding_type, recommended actions, and rule_delta
        rejects or selects candidates for approval

  → Separate Approved Store 1 Patch Tool  (not yet implemented)
        operator provides explicit approval for selected candidates
        patch tool applies only approved deltas to the target agent's Store 1
        writes are scoped to target_agent_id only

  → Re-run validation
        verify Store 1 state post-patch
        confirm no unintended side effects
```

No shortcut through this path is authorized. No tool may skip steps.

---

## This Tool Does Not Apply Store 1 Updates

`tools/govmem/store1_delta.py` **does not apply Store 1 updates.**

It generates candidate files only. Every candidate is born with these invariants and they cannot be overridden by input data:

```json
{
  "store1_write_applied": false,
  "candidate_only": true,
  "shared_with_peer_agents": false,
  "operator_approval_required": true,
  "approved_by_operator": false,
  "promotion_status": "candidate_review_required",
  "safety_status": "candidate_only_not_applied",
  "abigail_training_eligible": false,
  "abigail_training_requires_approval": true,
  "agent_scope": "agent_local"
}
```

The tool exits with code 1 and writes no output if a security violation is detected.

---

## Security Violations

If any Store 2 input record contains:

- `enforcement_allowed: true`
- `store1_write_allowed: true`
- `abigail_training_allowed: true`

The generator prints `SECURITY_VIOLATION` to stderr, exits with code 1, and writes **no output files**. This check runs before any candidate is built or any output directory is created.

---

## Reviewer Report

Every run produces four output files under `--out` (default: `/tmp/govmem_store1_deltas/<run_id>/`):

| File | Contents |
|---|---|
| `store1_delta_candidates_<run_id>.jsonl` | All generated candidates |
| `rejected_for_promotion_<run_id>.jsonl` | Rejected input records with reasons |
| `promotion_review_<run_id>.json` | Machine-readable reviewer report |
| `promotion_review_<run_id>.md` | Human-readable reviewer report |

The reviewer report includes:

- Safety verdict (`CANDIDATES_ONLY_CONFIRMED`, `REVIEW_ONLY_NO_PROMOTION`, `REJECTION_ONLY`)
- Counts: total input, candidate, rejected, operational, review-only
- Breakdown by generation, level, sentinel source, and finding type
- Hard-zero confirmation fields: `store1_writes_applied: 0`, `peer_agent_writes_attempted: 0`, `abigail_training_writes_applied: 0`

---

## Summary of Candidate Invariants

| Field | Required Value at Generation |
|---|---|
| `artifact_type` | `store1_delta_candidate` |
| `store_target` | `store_1` |
| `store1_write_applied` | `false` |
| `candidate_only` | `true` |
| `agent_scope` | `agent_local` |
| `shared_with_peer_agents` | `false` |
| `abigail_training_eligible` | `false` |
| `abigail_training_requires_approval` | `true` |
| `operator_approval_required` | `true` |
| `approved_by_operator` | `false` |
| `promotion_status` | `candidate_review_required` |
| `safety_status` | `candidate_only_not_applied` |
| `source_store` | `store_2` |
| `source_taxonomy` | `TAX2` |

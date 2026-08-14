"""
GovMem Store 1 Delta Candidate Generator — v3.0
LOGOS Governance Systems Inc.

Reads Store 2 analysis artifacts and produces candidate Store 1 deltas
for human/operator review.

This tool:
  - Never applies Store 1 deltas
  - Never writes operational Store 1 memory
  - Never calls endpoints
  - Never mutates GovMem runtime state
  - Never trains Abigail automatically

Architecture law:
  Shared doctrine, isolated learning.
  Shared audit, scoped promotion.
  Shared analysis, gated enforcement.
  Abigail may aggregate; agents may not overwrite each other.

Usage:
    python3 tools/govmem/store1_delta.py \\
        --store2 <path-to-store2-jsonl> \\
        [--report <optional-reviewer-report-json>] \\
        --agent-id <required-target-agent-id> \\
        [--agent-role <optional-target-agent-role>] \\
        [--run-id <optional-run-id>] \\
        [--out <optional-output-directory>]
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

TOOL_VERSION = "3.0"

VALID_SENTINEL_SOURCES = {"heuristic_simulation", "sentinel_overwatch", "legacy_no_source"}
VALID_GENERATIONS = {"G2", "G3", "G4", "G5", "G6"}
VALID_LEVELS = {"A", "B", "C", "D"}

# promotion_status values that indicate a record has already been applied
ALREADY_APPLIED_STATUSES = {"applied", "promoted", "store1_applied", "store1_written"}


# ─────────────────────────────────────────────────────────────────────────────
#  VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

def check_security_violation(record: dict, lineno: int) -> str | None:
    """Return a violation description string if this record is a security violation."""
    if record.get("enforcement_allowed") is True:
        return f"enforcement_allowed:true on line {lineno}"
    if record.get("store1_write_allowed") is True:
        return f"store1_write_allowed:true on line {lineno}"
    if record.get("abigail_training_allowed") is True:
        return f"abigail_training_allowed:true on line {lineno}"
    return None


def check_reject_reason(record: dict) -> str | None:
    """Return a rejection reason string, or None if the record is acceptable."""
    if record.get("store") != "store_2":
        return f"store_not_store2:{record.get('store')!r}"
    if record.get("scope") != "analysis_tooling_development":
        return f"scope_mismatch:{record.get('scope')!r}"
    ps = record.get("promotion_status", "")
    if ps in ALREADY_APPLIED_STATUSES:
        return f"already_applied:{ps!r}"
    sentinel_source = record.get("sentinel_source")
    if not sentinel_source:
        return "missing_sentinel_source"
    if sentinel_source not in VALID_SENTINEL_SOURCES:
        return f"unknown_sentinel_source:{sentinel_source!r}"
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  FINDING TYPE DERIVATION
# ─────────────────────────────────────────────────────────────────────────────

def derive_finding_type(sentinel_source: str, level: str, memory_action: str) -> str:
    if sentinel_source == "heuristic_simulation":
        return "simulation_evidence_only"
    if sentinel_source == "legacy_no_source":
        return "legacy_analysis_only"
    if level == "D" and memory_action == "deny_promotion":
        return "high_risk_detection_confirmed"
    if level == "C" and memory_action == "quarantine":
        return "quarantine_detection_confirmed"
    return "review_required"


# ─────────────────────────────────────────────────────────────────────────────
#  RECOMMENDED ACTION DERIVATION
# ─────────────────────────────────────────────────────────────────────────────

def derive_recommended_actions(sentinel_source: str, level: str) -> dict:
    # Hard safety rule: heuristic and legacy sources are always review-only
    if sentinel_source in ("heuristic_simulation", "legacy_no_source"):
        return {
            "recommended_store1_action": "review_only_no_promotion",
            "recommended_memory_action": "none",
            "recommended_sentinel_action": "none",
            "recommended_haap_requirement": "none",
        }
    # sentinel_overwatch — level-based recommendations
    if level == "D":
        return {
            "recommended_store1_action": "candidate_deny_promotion_rule",
            "recommended_memory_action": "deny_promotion",
            "recommended_sentinel_action": "block_and_escalate",
            "recommended_haap_requirement": "required",
        }
    if level == "C":
        return {
            "recommended_store1_action": "candidate_quarantine_rule",
            "recommended_memory_action": "quarantine",
            "recommended_sentinel_action": "quarantine",
            "recommended_haap_requirement": "conditional",
        }
    # Level A or B
    return {
        "recommended_store1_action": "candidate_observation_rule",
        "recommended_memory_action": "do_not_promote",
        "recommended_sentinel_action": "flag",
        "recommended_haap_requirement": "none",
    }


# ─────────────────────────────────────────────────────────────────────────────
#  SOURCE RECORD ID
# ─────────────────────────────────────────────────────────────────────────────

def stable_record_id(record: dict, index: int) -> str:
    sig = record.get("signature_id", "")
    vid = record.get("vector_id", "")
    gen = record.get("generation", "")
    lvl = record.get("level", "")
    raw = f"{sig}|{vid}|{gen}|{lvl}|{index}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


# ─────────────────────────────────────────────────────────────────────────────
#  RULE DELTA
# ─────────────────────────────────────────────────────────────────────────────

def sanitized_rule_delta(record: dict, finding_type: str) -> str:
    vid = record.get("vector_id", "unknown")
    gen = record.get("generation", "unknown")
    lvl = record.get("level", "unknown")
    dist = record.get("distortion_type", "")
    if finding_type in ("simulation_evidence_only", "legacy_analysis_only"):
        return f"review_only|{vid}|{gen}|level={lvl}"
    label = f"defensive_signature|{vid}|{gen}|level={lvl}"
    if dist:
        label += f"|{dist}"
    return label


# ─────────────────────────────────────────────────────────────────────────────
#  CANDIDATE BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def build_candidate(
    record: dict,
    index: int,
    agent_id: str,
    agent_role: str,
    source_file: str,
    created_at: str,
) -> dict:
    sentinel_source = record.get("sentinel_source", "")
    level = record.get("level", "unknown")
    memory_action = record.get("memory_action", "")
    sentinel_action = record.get("sentinel_action", "")
    haap_requirement = record.get("haap_requirement", "")
    audit_reason = record.get("audit_reason", "")

    finding_type = derive_finding_type(sentinel_source, level, memory_action)
    actions = derive_recommended_actions(sentinel_source, level)
    record_id = stable_record_id(record, index)
    rule_delta = sanitized_rule_delta(record, finding_type)

    return {
        "artifact_type": "store1_delta_candidate",
        "schema_version": "3.0",
        "store_target": "store_1",
        "store1_write_applied": False,
        "candidate_only": True,

        "target_agent_id": agent_id,
        "target_agent_role": agent_role,
        "agent_scope": "agent_local",
        "shared_with_peer_agents": False,

        "shared_with_abigail": True,
        "abigail_training_eligible": False,
        "abigail_training_requires_approval": True,

        "source_store": "store_2",
        "source_run_id": record.get("run_id", ""),
        "source_taxonomy": "TAX2",
        "source_record_id": record_id,
        "sentinel_source": sentinel_source,

        "generation": record.get("generation", ""),
        "vector_id": record.get("vector_id", ""),
        "level": level,
        "memory_action_observed": memory_action,
        "sentinel_action_observed": sentinel_action,
        "haap_requirement_observed": haap_requirement,

        "finding_type": finding_type,
        "recommended_store1_action": actions["recommended_store1_action"],
        "recommended_memory_action": actions["recommended_memory_action"],
        "recommended_sentinel_action": actions["recommended_sentinel_action"],
        "recommended_haap_requirement": actions["recommended_haap_requirement"],

        "rule_delta": rule_delta,
        "audit_reason": audit_reason,
        "operator_approval_required": True,
        "approved_by_operator": False,
        "promotion_status": "candidate_review_required",

        "safety_status": "candidate_only_not_applied",
        "created_at": created_at,
        "source_file": source_file,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  REPORT BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def build_reviewer_report(
    run_id: str,
    agent_id: str,
    agent_role: str,
    source_store2_file: str,
    total: int,
    candidates: list[dict],
    rejected: list[dict],
) -> dict:
    by_gen: dict[str, int] = {}
    by_level: dict[str, int] = {}
    by_ss: dict[str, int] = {}
    by_ft: dict[str, int] = {}
    operational = 0
    review_only = 0

    for c in candidates:
        g = c.get("generation", "unknown")
        by_gen[g] = by_gen.get(g, 0) + 1

        lv = c.get("level", "unknown")
        by_level[lv] = by_level.get(lv, 0) + 1

        ss = c.get("sentinel_source", "unknown")
        by_ss[ss] = by_ss.get(ss, 0) + 1

        ft = c.get("finding_type", "unknown")
        by_ft[ft] = by_ft.get(ft, 0) + 1

        if c.get("recommended_store1_action") == "review_only_no_promotion":
            review_only += 1
        else:
            operational += 1

    if total > 0 and len(candidates) == 0:
        safety_verdict = "REJECTION_ONLY"
    elif operational > 0:
        safety_verdict = "CANDIDATES_ONLY_CONFIRMED"
    elif review_only > 0:
        safety_verdict = "REVIEW_ONLY_NO_PROMOTION"
    else:
        safety_verdict = "REJECTION_ONLY"

    return {
        "run_id": run_id,
        "target_agent_id": agent_id,
        "target_agent_role": agent_role,
        "source_store2_file": source_store2_file,
        "total_input_records": total,
        "candidate_records": len(candidates),
        "rejected_records": len(rejected),
        "records_by_generation": by_gen,
        "records_by_level": by_level,
        "records_by_sentinel_source": by_ss,
        "candidates_by_finding_type": by_ft,
        "operational_candidates": operational,
        "review_only_candidates": review_only,
        "store1_writes_applied": 0,
        "peer_agent_writes_attempted": 0,
        "abigail_training_writes_applied": 0,
        "safety_verdict": safety_verdict,
    }


def build_markdown_report(report: dict, rejected: list[dict]) -> str:
    r = report
    lines = [
        "# GovMem Store 1 Delta — Promotion Review Report",
        "",
        f"**Run ID:** {r['run_id']}",
        f"**Target Agent:** {r['target_agent_id']} ({r['target_agent_role']})",
        f"**Source Store 2:** {r['source_store2_file']}",
        "",
        "## Summary",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Total input records | {r['total_input_records']} |",
        f"| Candidate records | {r['candidate_records']} |",
        f"| Rejected records | {r['rejected_records']} |",
        f"| Operational candidates | {r['operational_candidates']} |",
        f"| Review-only candidates | {r['review_only_candidates']} |",
        "",
        f"## Safety Verdict: {r['safety_verdict']}",
        "",
    ]

    if r["safety_verdict"] == "REVIEW_ONLY_NO_PROMOTION":
        lines += [
            "All candidates are review-only (heuristic simulation or legacy source).",
            "No operational Store 1 action is recommended.",
            "",
            "**Store 1 writes applied: 0**",
            "**Abigail training writes: 0**",
            "**Peer agent writes attempted: 0**",
        ]
    elif r["safety_verdict"] == "CANDIDATES_ONLY_CONFIRMED":
        lines += [
            f"**{r['operational_candidates']} operational candidate(s) require operator review.**",
            "No deltas have been applied. Operator approval required before any promotion.",
            "",
            "**Store 1 writes applied: 0**",
            "**Abigail training writes: 0**",
            "**Peer agent writes attempted: 0**",
        ]
    else:
        lines += [
            "No candidates were generated. Review rejection log for details.",
        ]

    lines += [
        "",
        "## Candidates by Finding Type",
        "",
        "| Finding Type | Count |",
        "|---|---|",
    ]
    for ft, count in sorted(r["candidates_by_finding_type"].items()):
        lines.append(f"| {ft} | {count} |")

    lines += [
        "",
        "## Candidates by Generation",
        "",
        "| Generation | Count |",
        "|---|---|",
    ]
    for gen, count in sorted(r["records_by_generation"].items()):
        lines.append(f"| {gen} | {count} |")

    lines += [
        "",
        "## Candidates by Level",
        "",
        "| Level | Count |",
        "|---|---|",
    ]
    for lvl, count in sorted(r["records_by_level"].items()):
        lines.append(f"| {lvl} | {count} |")

    lines += [
        "",
        "## Candidates by Sentinel Source",
        "",
        "| Source | Count |",
        "|---|---|",
    ]
    for src, count in sorted(r["records_by_sentinel_source"].items()):
        lines.append(f"| {src} | {count} |")

    lines += ["", "## Rejection Details", ""]
    if rejected:
        lines += [
            "| # | vector_id | reason |",
            "|---|---|---|",
        ]
        for i, rej in enumerate(rejected[:50], 1):
            vid = rej.get("vector_id", rej.get("_input_vector_id", ""))
            reason = rej.get("rejection_reason", "unknown")
            lines.append(f"| {i} | {vid} | {reason} |")
        if len(rejected) > 50:
            lines.append(f"| ... | *(and {len(rejected) - 50} more)* | |")
    else:
        lines.append("No rejections.")

    lines += [
        "",
        "## Operator Action Required",
        "",
    ]
    if r["safety_verdict"] == "REVIEW_ONLY_NO_PROMOTION":
        lines.append(
            "None. All candidates are review-only. "
            "No Store 1 delta is recommended at this time."
        )
    elif r["safety_verdict"] == "CANDIDATES_ONLY_CONFIRMED":
        lines += [
            f"Operator review required for {r['operational_candidates']} candidate(s).",
            "",
            "To promote a candidate to Store 1, an authorized operator must:",
            "1. Review the candidate JSONL output.",
            "2. Approve specific candidates by source_record_id.",
            "3. Run the separate approved Store 1 patch tool.",
            "",
            "**This tool does NOT apply Store 1 updates.**",
        ]
    else:
        lines.append("No candidates generated — review rejection log.")

    return "\n".join(lines) + "\n"


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="GovMem Store 1 Delta Candidate Generator v3.0 — review-only, no writes"
    )
    parser.add_argument("--store2", required=True,
                        help="Path to Store 2 JSONL file")
    parser.add_argument("--report", default=None,
                        help="Optional path to existing reviewer report JSON (metadata only)")
    parser.add_argument("--agent-id", required=True,
                        help="Target agent ID for scoped delta candidates")
    parser.add_argument("--agent-role", default="unknown",
                        help="Target agent role (default: unknown)")
    parser.add_argument("--run-id", default=None,
                        help="Explicit run ID (default: from Store 2 record or UTC timestamp)")
    parser.add_argument("--out", default=None,
                        help="Output directory (default: /tmp/govmem_store1_deltas/<run_id>/)")
    args = parser.parse_args()

    store2_path = Path(args.store2).resolve()
    if not store2_path.exists():
        print(f"ERROR: Store 2 file not found: {store2_path}", file=sys.stderr)
        return 1

    source_file = str(store2_path)
    created_at = datetime.now(timezone.utc).isoformat()
    agent_role = args.agent_role or "unknown"

    candidates: list[dict] = []
    rejected: list[dict] = []
    total = 0
    run_id_from_store2: str | None = None

    with store2_path.open() as fh:
        for lineno, raw_line in enumerate(fh, 1):
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            total += 1

            try:
                record = json.loads(raw_line)
            except json.JSONDecodeError as e:
                rejected.append({
                    "_line": lineno,
                    "vector_id": "",
                    "rejection_reason": f"invalid_json:{e}",
                })
                continue

            # Security violation check — exit immediately, write no output
            violation = check_security_violation(record, lineno)
            if violation:
                print(f"SECURITY_VIOLATION: {violation}", file=sys.stderr)
                print("Aborting. No candidates were written.", file=sys.stderr)
                return 1

            reject_reason = check_reject_reason(record)
            if reject_reason:
                rejected.append({
                    "_line": lineno,
                    "vector_id": record.get("vector_id", ""),
                    "rejection_reason": reject_reason,
                })
                continue

            if run_id_from_store2 is None:
                run_id_from_store2 = record.get("run_id") or None

            index = len(candidates) + len(rejected)
            candidate = build_candidate(
                record=record,
                index=index,
                agent_id=args.agent_id,
                agent_role=agent_role,
                source_file=source_file,
                created_at=created_at,
            )
            candidates.append(candidate)

    run_id = (
        args.run_id
        or run_id_from_store2
        or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    )
    out_dir = (
        Path(args.out).resolve()
        if args.out
        else Path(f"/tmp/govmem_store1_deltas/{run_id}")
    )

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"ERROR: cannot create output directory {out_dir}: {e}", file=sys.stderr)
        return 1

    report = build_reviewer_report(
        run_id=run_id,
        agent_id=args.agent_id,
        agent_role=agent_role,
        source_store2_file=source_file,
        total=total,
        candidates=candidates,
        rejected=rejected,
    )
    md_report = build_markdown_report(report, rejected)

    cand_path = out_dir / f"store1_delta_candidates_{run_id}.jsonl"
    rejected_path = out_dir / f"rejected_for_promotion_{run_id}.jsonl"
    report_json_path = out_dir / f"promotion_review_{run_id}.json"
    report_md_path = out_dir / f"promotion_review_{run_id}.md"

    with cand_path.open("w") as fh:
        for c in candidates:
            fh.write(json.dumps(c) + "\n")

    with rejected_path.open("w") as fh:
        for r in rejected:
            fh.write(json.dumps(r) + "\n")

    with report_json_path.open("w") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")

    with report_md_path.open("w") as fh:
        fh.write(md_report)

    print(f"Store 1 Delta Generator v{TOOL_VERSION} — Run {run_id}")
    print(f"  Store 2:  {source_file}")
    print(f"  Agent:    {args.agent_id} ({agent_role})")
    print(f"  Records:  {total} input / {len(candidates)} candidates / {len(rejected)} rejected")
    print(f"  Verdict:  {report['safety_verdict']}")
    print(f"  Output:   {out_dir}/")
    print(f"    {cand_path.name}  ({len(candidates)} candidates)")
    print(f"    {rejected_path.name}  ({len(rejected)} records)")
    print(f"    {report_json_path.name}")
    print(f"    {report_md_path.name}")
    print("")
    print("  Store 1 writes applied:          0")
    print("  Abigail training writes applied:  0")
    print("  Peer agent writes attempted:      0")

    if total > 0 and len(candidates) == 0:
        print(
            f"\nWARNING: all {len(rejected)} record(s) rejected. "
            "Check rejected JSONL for reasons.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

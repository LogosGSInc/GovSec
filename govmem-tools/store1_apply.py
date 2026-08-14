"""
GovMem Store 1 Apply Gate — v1.0
LOGOS Governance Systems Inc.

Applies operator-approved Store 1 delta candidates into per-agent,
file-backed Store 1 artifacts under /tmp by default.

This tool:
  - Never writes to live runtime memory
  - Never calls endpoints
  - Never trains Abigail
  - Never mutates Sentinel or OverWatch behavior
  - Never writes outside the selected root
  - Applies only candidates explicitly approved in an operator manifest
  - Accepts only sentinel_overwatch provenance as Store 1 operational truth

Architecture law:
  Shared doctrine, isolated learning.
  Shared audit, scoped promotion.
  Shared analysis, gated enforcement.
  Abigail may aggregate; agents may not overwrite each other.

Usage:
    python3 tools/govmem/store1_apply.py \\
        --candidates <path-to-store1_delta_candidates_jsonl> \\
        --approval-manifest <path-to-approval-manifest-json> \\
        --agent-id <required-target-agent-id> \\
        [--agent-role <optional-agent-role>] \\
        [--run-id <optional-run-id>] \\
        [--root <optional-output-root>]
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

TOOL_VERSION = "1.0"

DEFAULT_ROOT = "/tmp/govmem_store1/"

# Only this provenance may become Store 1 operational truth
ALLOWED_SENTINEL_SOURCE = "sentinel_overwatch"
FORBIDDEN_SENTINEL_SOURCES = {"heuristic_simulation", "legacy_no_source"}

# Safe identifier: no path traversal, no separators, no absolute path content
SAFE_AGENT_ID = re.compile(r"^[A-Za-z0-9_-]+$")
SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9._-]+$")


# ─────────────────────────────────────────────────────────────────────────────
#  WRITE-GATE VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

def check_write_gate(candidate: dict, agent_id: str) -> str | None:
    """Return a soft-rejection reason, or None if the candidate passes the gate."""
    if candidate.get("artifact_type") != "store1_delta_candidate":
        return f"artifact_type_mismatch:{candidate.get('artifact_type')!r}"
    if candidate.get("candidate_only") is not True:
        return "candidate_only_not_true"
    if candidate.get("store1_write_applied") is not False:
        return "store1_write_applied_not_false"
    if candidate.get("store_target") != "store_1":
        return f"store_target_mismatch:{candidate.get('store_target')!r}"
    if candidate.get("promotion_status") != "candidate_review_required":
        return f"promotion_status_mismatch:{candidate.get('promotion_status')!r}"

    target = candidate.get("target_agent_id")
    if not target:
        return "missing_target_agent_id"
    if target != agent_id:
        return "agent_id_mismatch"

    if candidate.get("shared_with_peer_agents") is not False:
        return "shared_with_peer_agents_not_false"
    if candidate.get("operator_approval_required") is not True:
        return "operator_approval_required_not_true"
    if candidate.get("approved_by_operator") is not False:
        return "approved_by_operator_not_false_on_candidate"
    if not candidate.get("source_record_id"):
        return "missing_source_record_id"

    return None


def check_provenance(candidate: dict) -> str | None:
    """Return a soft-rejection reason for non-eligible provenance, or None."""
    source = candidate.get("sentinel_source")
    if source == ALLOWED_SENTINEL_SOURCE:
        return None
    if source in FORBIDDEN_SENTINEL_SOURCES:
        return f"sentinel_source_not_operational:{source}"
    return f"unknown_sentinel_source:{source!r}"


def check_approval(approval: dict) -> str | None:
    """Validate a matched approval manifest entry."""
    if not approval.get("approval_id"):
        return "manifest_missing_approval_id"
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  APPLIED RECORD BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def build_applied_record(
    candidate: dict,
    approval: dict,
    manifest: dict,
    agent_id: str,
    agent_role: str,
    applied_at: str,
    source_file: str,
) -> dict:
    vector_id = candidate.get("vector_id", "")
    generation = candidate.get("generation", "")
    level = candidate.get("level", "")
    store1_action = candidate.get("recommended_store1_action", "")

    operational_effect = (
        f"Apply {store1_action} for {vector_id} ({generation}/level {level}) "
        f"to agent {agent_id}"
    )

    return {
        "store": "store_1",
        "schema_version": "1.0",

        "target_agent_id": agent_id,
        "target_agent_role": agent_role,
        "agent_scope": "agent_local",
        "shared_with_peer_agents": False,
        "shared_with_abigail": candidate.get("shared_with_abigail", False),

        "source_delta_id": candidate.get("source_record_id", ""),
        "source_store2_run_id": candidate.get("source_run_id", ""),
        "source_taxonomy": candidate.get("source_taxonomy", "TAX2"),
        "sentinel_source": candidate.get("sentinel_source", ""),

        "vector_id": vector_id,
        "generation": generation,
        "level": level,

        "approved_by_operator": True,
        "approval_id": approval.get("approval_id", ""),
        "approved_at": manifest.get("approved_at", ""),
        "approved_by": manifest.get("approved_by", ""),

        "operational_effect": operational_effect,
        "memory_action": candidate.get("recommended_memory_action", ""),
        "sentinel_action": candidate.get("recommended_sentinel_action", ""),
        "haap_requirement": candidate.get("recommended_haap_requirement", ""),
        "confidence_delta": 0.0,

        "expiration": None,
        "review_after": None,
        "rollback_id": None,

        "abigail_training_eligible": False,
        "abigail_training_requires_approval": True,

        "safety_status": "store1_applied_approved",
        "applied_at": applied_at,
        "source_file": source_file,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  APPLY LOG
# ─────────────────────────────────────────────────────────────────────────────

def build_apply_log(
    run_id: str,
    root: str,
    agent_id: str,
    agent_role: str,
    candidates_file: str,
    manifest_file: str,
    applied: list[dict],
    rejected: list[dict],
    abigail_count: int,
    output_files: list[str],
) -> dict:
    by_gen: dict[str, int] = {}
    by_level: dict[str, int] = {}
    by_ss: dict[str, int] = {}

    for r in applied:
        g = r.get("generation", "unknown")
        by_gen[g] = by_gen.get(g, 0) + 1
        lv = r.get("level", "unknown")
        by_level[lv] = by_level.get(lv, 0) + 1
        ss = r.get("sentinel_source", "unknown")
        by_ss[ss] = by_ss.get(ss, 0) + 1

    if applied:
        safety_verdict = "STORE1_APPLY_CONFIRMED"
    else:
        safety_verdict = "REJECTION_ONLY"

    return {
        "run_id": run_id,
        "tool_version": TOOL_VERSION,
        "root": root,
        "target_agent_id": agent_id,
        "target_agent_role": agent_role,
        "candidates_file": candidates_file,
        "approval_manifest_file": manifest_file,
        "applied_records": len(applied),
        "rejected_records": len(rejected),
        "security_violations": 0,
        "abigail_aggregation_records": abigail_count,
        "store1_writes_applied": len(applied),
        "peer_agent_writes_attempted": 0,
        "abigail_training_writes_applied": 0,
        "records_by_generation": by_gen,
        "records_by_level": by_level,
        "records_by_sentinel_source": by_ss,
        "safety_verdict": safety_verdict,
        "output_files": output_files,
    }


def build_apply_log_md(log: dict, rejected: list[dict]) -> str:
    lines = [
        "# GovMem Store 1 Apply Gate — Apply Log",
        "",
        f"**Run ID:** {log['run_id']}",
        f"**Target Agent:** {log['target_agent_id']} ({log['target_agent_role']})",
        f"**Root:** {log['root']}",
        f"**Candidates:** {log['candidates_file']}",
        f"**Approval Manifest:** {log['approval_manifest_file']}",
        "",
        "## Summary",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Applied records | {log['applied_records']} |",
        f"| Rejected records | {log['rejected_records']} |",
        f"| Abigail aggregation copies | {log['abigail_aggregation_records']} |",
        f"| Store 1 writes applied (file-backed) | {log['store1_writes_applied']} |",
        f"| Peer agent writes attempted | {log['peer_agent_writes_attempted']} |",
        f"| Abigail training writes applied | {log['abigail_training_writes_applied']} |",
        "",
        f"## Safety Verdict: {log['safety_verdict']}",
        "",
        "All writes are file-backed under the selected root. "
        "No live runtime memory was mutated. No endpoints were called.",
        "",
        "## Rejections",
        "",
    ]
    if rejected:
        lines += ["| # | source_record_id | reason |", "|---|---|---|"]
        for i, rej in enumerate(rejected[:50], 1):
            lines.append(
                f"| {i} | {rej.get('source_record_id', '')} "
                f"| {rej.get('rejection_reason', 'unknown')} |"
            )
        if len(rejected) > 50:
            lines.append(f"| ... | *(and {len(rejected) - 50} more)* | |")
    else:
        lines.append("No rejections.")

    lines += ["", "## Output Files", ""]
    for f in log["output_files"]:
        lines.append(f"- `{f}`")

    return "\n".join(lines) + "\n"


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="GovMem Store 1 Apply Gate v1.0 — approval-gated, file-backed, per-agent"
    )
    parser.add_argument("--candidates", required=True,
                        help="Path to Store 1 delta candidates JSONL")
    parser.add_argument("--approval-manifest", required=True,
                        help="Path to operator approval manifest JSON")
    parser.add_argument("--agent-id", required=True,
                        help="Target agent ID; must match candidate target_agent_id")
    parser.add_argument("--agent-role", default="unknown",
                        help="Target agent role (default: unknown)")
    parser.add_argument("--run-id", default=None,
                        help="Explicit run ID (default: candidate source_run_id or UTC timestamp)")
    parser.add_argument("--root", default=DEFAULT_ROOT,
                        help=f"Output root directory (default: {DEFAULT_ROOT})")
    args = parser.parse_args()

    agent_id = args.agent_id
    agent_role = args.agent_role or "unknown"

    # ── HARD GATE: agent_id must be a safe path component ──────────────────
    if not SAFE_AGENT_ID.match(agent_id):
        print(
            f"SECURITY_VIOLATION: unsafe agent_id {agent_id!r} "
            "(path traversal or invalid characters)",
            file=sys.stderr,
        )
        print("Aborting. Nothing was written.", file=sys.stderr)
        return 1

    if args.run_id and not SAFE_RUN_ID.match(args.run_id):
        print(
            f"SECURITY_VIOLATION: unsafe run_id {args.run_id!r}",
            file=sys.stderr,
        )
        print("Aborting. Nothing was written.", file=sys.stderr)
        return 1

    candidates_path = Path(args.candidates).resolve()
    manifest_path = Path(args.approval_manifest).resolve()

    if not candidates_path.exists():
        print(f"ERROR: candidates file not found: {candidates_path}", file=sys.stderr)
        return 1
    if not manifest_path.exists():
        print(f"ERROR: approval manifest not found: {manifest_path}", file=sys.stderr)
        return 1

    # ── Load and validate manifest ──────────────────────────────────────────
    try:
        manifest = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as e:
        print(f"ERROR: invalid approval manifest JSON: {e}", file=sys.stderr)
        return 1

    if not manifest.get("approved_by"):
        print("ERROR: approval manifest missing approved_by", file=sys.stderr)
        return 1
    if not manifest.get("approved_at"):
        print("ERROR: approval manifest missing approved_at", file=sys.stderr)
        return 1

    approvals_by_id: dict[str, dict] = {}
    for entry in manifest.get("approvals", []):
        srid = entry.get("source_record_id")
        if srid:
            approvals_by_id[srid] = entry

    applied_at = datetime.now(timezone.utc).isoformat()
    source_file = str(candidates_path)

    # ── Process candidates (no writes until all security checks pass) ───────
    applied: list[dict] = []
    rejected: list[dict] = []
    run_id_from_candidates: str | None = None

    with candidates_path.open() as fh:
        for lineno, raw_line in enumerate(fh, 1):
            raw_line = raw_line.strip()
            if not raw_line:
                continue

            try:
                candidate = json.loads(raw_line)
            except json.JSONDecodeError as e:
                rejected.append({
                    "_line": lineno,
                    "source_record_id": "",
                    "rejection_reason": f"invalid_json:{e}",
                })
                continue

            srid = candidate.get("source_record_id", "")
            sentinel_source = candidate.get("sentinel_source")

            # ── HARD GATE: forged approval of non-operational provenance ───
            # A manifest that approves a heuristic_simulation or
            # legacy_no_source candidate is a forged approval attempt.
            if sentinel_source in FORBIDDEN_SENTINEL_SOURCES and srid in approvals_by_id:
                print(
                    f"SECURITY_VIOLATION: approval manifest approves candidate "
                    f"{srid} with sentinel_source={sentinel_source!r} on line {lineno}. "
                    "Non-operational provenance cannot become Store 1 truth.",
                    file=sys.stderr,
                )
                print("Aborting. No approved records were written.", file=sys.stderr)
                return 1

            if run_id_from_candidates is None:
                cand_run = candidate.get("source_run_id")
                if cand_run and SAFE_RUN_ID.match(str(cand_run)):
                    run_id_from_candidates = str(cand_run)

            # ── Write-gate (soft rejections) ────────────────────────────────
            reason = check_write_gate(candidate, agent_id)
            if reason is None:
                reason = check_provenance(candidate)
            if reason is None and srid not in approvals_by_id:
                reason = "not_in_approval_manifest"
            if reason is None:
                reason = check_approval(approvals_by_id[srid])

            if reason:
                rejected.append({
                    "_line": lineno,
                    "source_record_id": srid,
                    "vector_id": candidate.get("vector_id", ""),
                    "sentinel_source": sentinel_source,
                    "rejection_reason": reason,
                })
                continue

            record = build_applied_record(
                candidate=candidate,
                approval=approvals_by_id[srid],
                manifest=manifest,
                agent_id=agent_id,
                agent_role=agent_role,
                applied_at=applied_at,
                source_file=source_file,
            )
            applied.append(record)

    run_id = (
        args.run_id
        or run_id_from_candidates
        or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    )

    # ── Build output paths and verify containment under root ────────────────
    root = Path(args.root).resolve()
    agent_dir = root / "agents" / agent_id
    approved_path = agent_dir / "approved" / f"store1_{agent_id}_{run_id}.jsonl"
    rejected_path = agent_dir / "rejected" / f"rejected_{agent_id}_{run_id}.jsonl"
    abigail_path = root / "abigail" / "aggregation" / f"abigail_agg_{run_id}.jsonl"
    log_json_path = root / "apply_log" / f"apply_log_{run_id}.json"
    log_md_path = root / "apply_log" / f"apply_log_{run_id}.md"

    all_outputs = [approved_path, rejected_path, abigail_path, log_json_path, log_md_path]
    for p in all_outputs:
        if not p.resolve().is_relative_to(root):
            print(
                f"SECURITY_VIOLATION: output path escapes root: {p}",
                file=sys.stderr,
            )
            print("Aborting. Nothing was written.", file=sys.stderr)
            return 1

    # ── Abigail aggregation copies (read-view only) ──────────────────────────
    abigail_records = [r for r in applied if r.get("shared_with_abigail") is True]

    # ── Write outputs ────────────────────────────────────────────────────────
    written_files: list[str] = []
    try:
        approved_path.parent.mkdir(parents=True, exist_ok=True)
        rejected_path.parent.mkdir(parents=True, exist_ok=True)
        abigail_path.parent.mkdir(parents=True, exist_ok=True)
        log_json_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"ERROR: cannot create output directories under {root}: {e}", file=sys.stderr)
        return 1

    with approved_path.open("w") as fh:
        for r in applied:
            fh.write(json.dumps(r) + "\n")
    written_files.append(str(approved_path))

    with rejected_path.open("w") as fh:
        for r in rejected:
            fh.write(json.dumps(r) + "\n")
    written_files.append(str(rejected_path))

    with abigail_path.open("w") as fh:
        for r in abigail_records:
            fh.write(json.dumps(r) + "\n")
    written_files.append(str(abigail_path))

    apply_log = build_apply_log(
        run_id=run_id,
        root=str(root),
        agent_id=agent_id,
        agent_role=agent_role,
        candidates_file=str(candidates_path),
        manifest_file=str(manifest_path),
        applied=applied,
        rejected=rejected,
        abigail_count=len(abigail_records),
        output_files=written_files + [str(log_json_path), str(log_md_path)],
    )

    with log_json_path.open("w") as fh:
        json.dump(apply_log, fh, indent=2)
        fh.write("\n")
    with log_md_path.open("w") as fh:
        fh.write(build_apply_log_md(apply_log, rejected))

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"Store 1 Apply Gate v{TOOL_VERSION} — Run {run_id}")
    print(f"  Candidates: {candidates_path}")
    print(f"  Manifest:   {manifest_path}")
    print(f"  Agent:      {agent_id} ({agent_role})")
    print(f"  Applied:    {len(applied)} record(s)")
    print(f"  Rejected:   {len(rejected)} record(s)")
    print(f"  Abigail:    {len(abigail_records)} aggregation cop(ies)")
    print(f"  Verdict:    {apply_log['safety_verdict']}")
    print(f"  Root:       {root}/")
    print(f"    {approved_path.relative_to(root)}")
    print(f"    {rejected_path.relative_to(root)}")
    print(f"    {abigail_path.relative_to(root)}")
    print(f"    {log_json_path.relative_to(root)}")
    print(f"    {log_md_path.relative_to(root)}")
    print("")
    print(f"  Store 1 writes applied (file-backed): {len(applied)}")
    print("  Peer agent writes attempted:          0")
    print("  Abigail training writes applied:      0")

    return 0


if __name__ == "__main__":
    sys.exit(main())

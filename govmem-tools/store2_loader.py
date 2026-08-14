"""
GovMem Store 2 Loader — v2B.1
LOGOS Governance Systems Inc.

Routes TAX2 govmem_ingest JSONL output into analysis-only Store 2 artifacts.

This loader:
  - Never writes to Store 1
  - Never mutates live GovMem memory
  - Never calls Abigail, Sentinel, OverWatch, or any endpoint
  - Never auto-promotes TAX2 output
  - Never trains Abigail

Architecture law:
  Shared doctrine, isolated learning.
  Shared audit, scoped promotion.
  Shared analysis, gated enforcement.
  Abigail may aggregate; agents may not overwrite each other.

Usage:
    python3 tools/govmem/store2_loader.py \\
        --govmem <path/to/govmem_ingest/*.jsonl> \\
        [--haap   <path/to/haap_audits/*.log>] \\
        [--run-id <explicit-run-id>] \\
        [--out    <output-directory>] \\
        [--allow-legacy-no-sentinel-source]
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

LOADER_VERSION = "2B.1"

VALID_GENERATIONS = {"G2", "G3", "G4", "G5", "G6"}
VALID_MEMORY_ACTIONS = {"do_not_promote", "quarantine", "deny_promotion"}
VALID_SENTINEL_SOURCES = {"heuristic_simulation", "sentinel_overwatch", "legacy_no_source"}
VALID_LEVELS = {"A", "B", "C", "D"}


# ─────────────────────────────────────────────────────────────────────────────
#  LEVEL DERIVATION
# ─────────────────────────────────────────────────────────────────────────────

def derive_level(record: dict) -> str:
    """Return level from input record or signature_id. Returns 'unknown' if not derivable."""
    lvl = record.get("level", "")
    if lvl in VALID_LEVELS:
        return lvl
    # Try to extract from signature_id: e.g. MT-G4-01-A-ef666bbc
    sig = record.get("signature_id", "")
    for candidate in VALID_LEVELS:
        if f"-{candidate}-" in sig:
            return candidate
    return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
#  PROMOTION STATUS DERIVATION
# ─────────────────────────────────────────────────────────────────────────────

def derive_promotion_status(sentinel_source: str, memory_action: str) -> str:
    if sentinel_source in ("heuristic_simulation", "legacy_no_source"):
        return "analysis_only"
    if sentinel_source == "sentinel_overwatch":
        if memory_action == "deny_promotion":
            return "denied"
        return "review_required"
    return "rejected"


# ─────────────────────────────────────────────────────────────────────────────
#  RECORD VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

def validate_record(raw: dict, allow_legacy: bool) -> tuple[str | None, str | None]:
    """
    Validate a parsed record dict.

    Returns (rejection_reason, security_violation_reason).
    Both None means the record is accepted.
    A non-None security_violation_reason means the loader must exit 1 immediately.
    """
    # Security violations — checked before anything else
    if raw.get("enforcement_allowed") is True:
        return None, "enforcement_allowed:true in input record"
    if raw.get("store1_write_allowed") is True:
        return None, "store1_write_allowed:true in input record"
    if raw.get("abigail_training_allowed") is True:
        return None, "abigail_training_allowed:true in input record"

    # Required fields
    if not raw.get("vector_id"):
        return "missing_vector_id", None

    generation = raw.get("generation", "")
    if generation not in VALID_GENERATIONS:
        return f"invalid_generation:{generation!r}", None

    memory_action = raw.get("memory_action", "")
    if memory_action not in VALID_MEMORY_ACTIONS:
        return f"invalid_memory_action:{memory_action!r}", None

    sentinel_source = raw.get("sentinel_source")

    if sentinel_source is None:
        if allow_legacy:
            # Will be rewritten to legacy_no_source downstream
            return None, None
        return "missing_sentinel_source", None

    if sentinel_source not in VALID_SENTINEL_SOURCES:
        return f"unknown_sentinel_source:{sentinel_source!r}", None

    # Heuristic simulation records must not request promotion
    if sentinel_source == "heuristic_simulation":
        if raw.get("promotion_status") not in (None, "analysis_only", ""):
            return "heuristic_promotion_attempt", None
        if raw.get("recommended_store1_delta") is not None:
            return "heuristic_promotion_attempt", None

    return None, None


# ─────────────────────────────────────────────────────────────────────────────
#  RECORD NORMALIZATION
# ─────────────────────────────────────────────────────────────────────────────

def normalize_record(raw: dict, run_id: str, source_file: str,
                     loaded_at: str, allow_legacy: bool) -> dict:
    """Build a normalized Store 2 record from a validated input record."""
    sentinel_source = raw.get("sentinel_source")
    if sentinel_source is None:
        # allow_legacy is guaranteed True here (validation already checked)
        sentinel_source = "legacy_no_source"

    memory_action = raw.get("memory_action", "")
    level = derive_level(raw)
    promotion_status = derive_promotion_status(sentinel_source, memory_action)

    return {
        "store": "store_2",
        "scope": "analysis_tooling_development",
        "run_id": run_id,
        "loader_version": LOADER_VERSION,
        "source_taxonomy": "TAX2",

        "signature_id": raw.get("signature_id", ""),
        "vector_id": raw.get("vector_id", ""),
        "generation": raw.get("generation", ""),
        "level": level,
        "stage": raw.get("stage", ""),
        "vector_name": raw.get("vector_name", ""),
        "distortion_type": raw.get("distortion_type", ""),
        "turn_span": raw.get("turn_span"),
        "confidence": raw.get("confidence"),

        "sentinel_source": sentinel_source,
        "sentinel_action": raw.get("sentinel_action", ""),
        "sentinel_reason": raw.get("sentinel_reason", ""),
        "memory_action": memory_action,
        "haap_requirement": raw.get("haap_requirement", ""),
        "bd1a_vectors": raw.get("bd1a_vectors", []),
        "phase_q_vectors": raw.get("phase_q_vectors", []),
        "audit_reason": raw.get("audit_reason", ""),

        # Hard invariants — overwritten unconditionally regardless of input
        "enforcement_allowed": False,
        "store1_write_allowed": False,
        "abigail_training_allowed": False,

        "promotion_status": promotion_status,
        "recommended_store1_delta": None,
        "safety_status": "store2_analysis_only",

        "loaded_at": loaded_at,
        "source_file": source_file,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  REPORT GENERATION
# ─────────────────────────────────────────────────────────────────────────────

def build_reviewer_report(
    run_id: str,
    source_govmem: str,
    source_haap: str | None,
    loaded_at: str,
    total: int,
    accepted: list[dict],
    rejected: list[dict],
) -> dict:
    by_generation: dict[str, int] = {}
    by_level: dict[str, int] = {}
    by_sentinel_source: dict[str, int] = {}
    by_memory_action: dict[str, int] = {}
    legacy_count = 0
    promotion_candidates = 0

    for r in accepted:
        g = r.get("generation", "unknown")
        by_generation[g] = by_generation.get(g, 0) + 1

        lv = r.get("level", "unknown")
        by_level[lv] = by_level.get(lv, 0) + 1

        ss = r.get("sentinel_source", "unknown")
        by_sentinel_source[ss] = by_sentinel_source.get(ss, 0) + 1

        ma = r.get("memory_action", "unknown")
        by_memory_action[ma] = by_memory_action.get(ma, 0) + 1

        if ss == "legacy_no_source":
            legacy_count += 1
        if r.get("promotion_status") == "review_required":
            promotion_candidates += 1

    level_d = sum(1 for r in accepted if r.get("level") == "D")
    level_c = sum(1 for r in accepted if r.get("level") == "C")
    all_heuristic = all(
        r.get("sentinel_source") in ("heuristic_simulation", "legacy_no_source")
        for r in accepted
    ) if accepted else True

    if len(accepted) == 0 and len(rejected) > 0:
        safety_verdict = "REJECTION_ONLY"
    elif promotion_candidates > 0:
        safety_verdict = "REVIEW_REQUIRED"
    else:
        safety_verdict = "ANALYSIS_ONLY_CONFIRMED"

    return {
        "run_id": run_id,
        "loader_version": LOADER_VERSION,
        "source_govmem_file": source_govmem,
        "source_haap_file": source_haap,
        "loaded_at": loaded_at,
        "total_input_records": total,
        "accepted_records": len(accepted),
        "rejected_records": len(rejected),
        "legacy_no_source_records": legacy_count,
        "records_by_generation": by_generation,
        "records_by_level": by_level,
        "records_by_sentinel_source": by_sentinel_source,
        "records_by_memory_action": by_memory_action,
        "level_d_count": level_d,
        "level_c_count": level_c,
        "promotion_candidates_count": promotion_candidates,
        "store1_writes_attempted": 0,
        "abigail_training_writes_attempted": 0,
        "enforcement_writes_attempted": 0,
        "all_sentinel_source_heuristic": all_heuristic,
        "safety_verdict": safety_verdict,
    }


def build_markdown_report(report: dict, rejected: list[dict]) -> str:
    r = report
    lines = [
        "# Store 2 Loader — Review Report",
        "",
        f"**Run ID:** {r['run_id']}",
        f"**Loaded at:** {r['loaded_at']}",
        f"**Loader version:** {r['loader_version']}",
        f"**Source (GovMem):** {r['source_govmem_file']}",
        f"**Source (HAAP):** {r['source_haap_file'] or 'not provided'}",
        "",
        "## Summary",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Total input records | {r['total_input_records']} |",
        f"| Accepted | {r['accepted_records']} |",
        f"| Rejected | {r['rejected_records']} |",
        f"| Legacy (no sentinel_source) | {r['legacy_no_source_records']} |",
        f"| Level D records | {r['level_d_count']} |",
        f"| Level C records | {r['level_c_count']} |",
        f"| Promotion candidates (review_required) | {r['promotion_candidates_count']} |",
        "",
        f"## Safety Verdict: {r['safety_verdict']}",
        "",
    ]

    if r["safety_verdict"] == "ANALYSIS_ONLY_CONFIRMED":
        lines += [
            "All records are heuristic simulation or legacy (no live Sentinel source).",
            "No operational writes occurred.",
        ]
    elif r["safety_verdict"] == "REVIEW_REQUIRED":
        lines += [
            f"**{r['promotion_candidates_count']} record(s) sourced from sentinel_overwatch.**",
            "Operator review required before any Store 1 delta.",
        ]
    else:
        lines += ["No records were accepted."]

    lines += [
        "",
        f"Store 1 writes attempted: **{r['store1_writes_attempted']}**",
        f"Enforcement writes attempted: **{r['enforcement_writes_attempted']}**",
        f"Abigail training writes attempted: **{r['abigail_training_writes_attempted']}**",
        "",
        "## Records by Generation",
        "",
        "| Generation | Count |",
        "|---|---|",
    ]
    for gen, count in sorted(r["records_by_generation"].items()):
        lines.append(f"| {gen} | {count} |")

    lines += [
        "",
        "## Records by Level",
        "",
        "| Level | Count |",
        "|---|---|",
    ]
    for lvl, count in sorted(r["records_by_level"].items()):
        lines.append(f"| {lvl} | {count} |")

    lines += [
        "",
        "## Records by Sentinel Source",
        "",
        "| Source | Count |",
        "|---|---|",
    ]
    for src, count in sorted(r["records_by_sentinel_source"].items()):
        lines.append(f"| {src} | {count} |")

    lines += [
        "",
        "## Records by Memory Action",
        "",
        "| Memory Action | Count |",
        "|---|---|",
    ]
    for ma, count in sorted(r["records_by_memory_action"].items()):
        lines.append(f"| {ma} | {count} |")

    lines += ["", "## Rejection Details", ""]
    if rejected:
        lines += [
            "| # | vector_id | reason |",
            "|---|---|---|",
        ]
        for i, rej in enumerate(rejected[:50], 1):
            vid = rej.get("vector_id") or rej.get("_input_vector_id", "")
            reason = rej.get("rejection_reason", "unknown")
            lines.append(f"| {i} | {vid} | {reason} |")
        if len(rejected) > 50:
            lines.append(f"| ... | *(and {len(rejected) - 50} more)* | |")
    else:
        lines.append("No rejections.")

    lines += [
        "",
        "## Reviewer Action Required",
        "",
    ]
    if r["safety_verdict"] == "ANALYSIS_ONLY_CONFIRMED":
        lines.append(
            "None. All records are analysis-only. "
            "No Store 1 delta is recommended at this time."
        )
    elif r["safety_verdict"] == "REVIEW_REQUIRED":
        lines += [
            f"Operator review required for {r['promotion_candidates_count']} "
            "record(s) with `promotion_status: review_required`.",
            "",
            "To promote any record to Store 1, run the Store 1 delta patch tool",
            "(Correction 3 — not yet implemented) with explicit `--approve <signature_id>`.",
            "Do not bulk-import Store 2 artifacts into Store 1.",
        ]
    else:
        lines.append("No accepted records — review rejection log.")

    return "\n".join(lines) + "\n"


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="GovMem Store 2 Loader v2B.1 — analysis-only TAX2 ingest"
    )
    parser.add_argument("--govmem", required=True,
                        help="Path to govmem_ingest JSONL file")
    parser.add_argument("--haap", default=None,
                        help="Optional path to haap_audits log file")
    parser.add_argument("--run-id", default=None,
                        help="Explicit run ID (default: UTC timestamp)")
    parser.add_argument("--out", default=None,
                        help="Output directory (default: /tmp/govmem_store2/<run_id>/)")
    parser.add_argument("--allow-legacy-no-sentinel-source", action="store_true",
                        default=False,
                        help="Accept records missing sentinel_source as legacy_no_source")
    args = parser.parse_args()

    run_id = args.run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    loaded_at = datetime.now(timezone.utc).isoformat()
    allow_legacy = args.allow_legacy_no_sentinel_source

    govmem_path = Path(args.govmem).resolve()
    haap_path = Path(args.haap).resolve() if args.haap else None
    out_dir = Path(args.out).resolve() if args.out else Path(f"/tmp/govmem_store2/{run_id}")

    # Validate inputs exist
    if not govmem_path.exists():
        print(f"ERROR: govmem file not found: {govmem_path}", file=sys.stderr)
        return 1

    if haap_path and not haap_path.exists():
        print(f"ERROR: haap file not found: {haap_path}", file=sys.stderr)
        return 1

    # Create output directory
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"ERROR: cannot create output directory {out_dir}: {e}", file=sys.stderr)
        return 1

    source_govmem_str = str(govmem_path)
    source_haap_str = str(haap_path) if haap_path else None

    accepted: list[dict] = []
    rejected: list[dict] = []
    total = 0

    # Process records
    with govmem_path.open() as fh:
        for lineno, raw_line in enumerate(fh, 1):
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            total += 1

            # Parse JSON
            try:
                record = json.loads(raw_line)
            except json.JSONDecodeError as e:
                rejected.append({
                    "_line": lineno,
                    "_input_vector_id": "",
                    "rejection_reason": f"invalid_json:{e}",
                    "promotion_status": "rejected",
                })
                continue

            # Validate — security violations cause immediate exit
            reject_reason, security_violation = validate_record(record, allow_legacy)

            if security_violation:
                msg = (
                    f"SECURITY_VIOLATION on line {lineno}: {security_violation}\n"
                    "Loader aborting. No Store 2 output was written."
                )
                print(msg, file=sys.stderr)
                return 1

            if reject_reason:
                rejected.append({
                    "_line": lineno,
                    "_input_vector_id": record.get("vector_id", ""),
                    "vector_id": record.get("vector_id", ""),
                    "rejection_reason": reject_reason,
                    "promotion_status": "rejected",
                })
                continue

            normalized = normalize_record(
                record, run_id, source_govmem_str, loaded_at, allow_legacy
            )
            accepted.append(normalized)

    # Build report
    report = build_reviewer_report(
        run_id=run_id,
        source_govmem=source_govmem_str,
        source_haap=source_haap_str,
        loaded_at=loaded_at,
        total=total,
        accepted=accepted,
        rejected=rejected,
    )
    md_report = build_markdown_report(report, rejected)

    # Write outputs
    store2_path = out_dir / f"store2_{run_id}.jsonl"
    rejected_path = out_dir / f"rejected_{run_id}.jsonl"
    report_json_path = out_dir / f"reviewer_report_{run_id}.json"
    report_md_path = out_dir / f"reviewer_report_{run_id}.md"

    with store2_path.open("w") as fh:
        for rec in accepted:
            fh.write(json.dumps(rec) + "\n")

    with rejected_path.open("w") as fh:
        for rec in rejected:
            fh.write(json.dumps(rec) + "\n")

    with report_json_path.open("w") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")

    with report_md_path.open("w") as fh:
        fh.write(md_report)

    # Print summary
    print(f"Store 2 Loader v{LOADER_VERSION} — Run {run_id}")
    print(f"  Input:    {source_govmem_str}")
    print(f"  Records:  {total} input / {len(accepted)} accepted / {len(rejected)} rejected")
    print(f"  Verdict:  {report['safety_verdict']}")
    print(f"  Output:   {out_dir}/")
    print(f"    {store2_path.name}  ({len(accepted)} records)")
    print(f"    {rejected_path.name}  ({len(rejected)} records)")
    print(f"    {report_json_path.name}")
    print(f"    {report_md_path.name}")

    # Exit nonzero if all records were rejected and none accepted
    if total > 0 and len(accepted) == 0:
        print(
            f"\nERROR: all {len(rejected)} record(s) rejected. "
            "Check rejected JSONL for reasons.",
            file=sys.stderr,
        )
        if not allow_legacy and any(
            "missing_sentinel_source" in r.get("rejection_reason", "") for r in rejected
        ):
            print(
                "HINT: records are missing sentinel_source. "
                "Use --allow-legacy-no-sentinel-source for pre-Correction-1 artifacts.",
                file=sys.stderr,
            )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

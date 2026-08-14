"""
LOGOS ASF — TR-04D DEP.KEYSTONE / GovSec V2 Training Ingress Gate v1.0.0
LOGOS Governance Systems Inc.

Abigail-side bridge that references DEP.KEYSTONE trust-bundle evidence and
enforces GovSec V2 training-source admissibility. DEP.KEYSTONE
(LogosGSInc/dep.keystone) is a standalone supply-chain trust product that
emits verification-report.json, evidence.sha256, and sbom.cdx.json. Abigail
consumes those outputs; Abigail does not redefine or duplicate DEP.KEYSTONE.

GovSec V2 / Layer Zero is the broader training-admissibility doctrine.
DEP.KEYSTONE supply-chain trust checks are one required input to that doctrine.
Source Registry clearance and Clearance Ledger approval are separate gates.

Recon result (2026-06-27): No pre-existing DEP.KEYSTONE / GovSec training-ingress
gate was found in the LOGOS ASF codebase. A grep of training/, abigail/,
governance-spine/, agents/, and docs/ for DEP, KEYSTONE, Keystone, GovSec,
Layer Zero, Perceptual, admissibility, ingress, trust certificate, sbom, and
related field names returned no matches for a callable training-ingress gate.
DEPT- occurrences were department identifiers only. This module implements the
missing gate.

No real training occurs here. No model weights. No Store 1 writes. TR-05 was
not started here.
"""
import json
from pathlib import Path

INGRESS_VERSION = "dep_keystone_ingress:1.0.0"
SCHEMA_VERSION = "1.0.0"

VALID_GOVSEC_ADMISSIBILITY_STATUSES = frozenset({
    "draft", "pending", "approved", "rejected", "blocked", "archived",
})
VALID_GOVSEC_ADMISSIBILITY_DECISIONS = frozenset({
    "accepted_for_clearance",
    "rejected_at_ingress",
    "blocked_at_ingress",
    "requires_more_evidence",
})
VALID_DEP_KEYSTONE_STATUSES = frozenset({"VERIFIED", "FAILED"})
VALID_GOVSEC_LAYERS = frozenset({
    "layer_zero_reality_formation",
    "dep_keystone_supply_chain",
    "training_readiness_ingress",
})
VALID_NEXT_GATES = frozenset({
    "tr04a_source_registry",
    "tr04a_clearance_ledger",
    "synthetic_doctrine",
    "synthetic_review_bridge",
    "tr03_dataset_builder",
    "tr04b_dry_run",
    "tr05_model_registry",
})

_BLOCKED_STATUSES = frozenset({"blocked", "rejected", "archived"})
_PENDING_STATUSES  = frozenset({"draft", "pending"})

REQUIRED_FIELDS = frozenset({
    "dep_keystone_ingress_id",
    "schema_version",
    "created_at",
    "source_id",
    "source_name",
    "source_type",
    "classification",
    "dep_keystone_project_name",
    "dep_keystone_status",
    "dep_keystone_trust_score",
    "dep_keystone_findings_count",
    "dep_keystone_haap_drs_escalation_required",
    "dep_keystone_verification_report_ref",
    "dep_keystone_evidence_sha256_ref",
    "dep_keystone_sbom_ref",
    "dep_keystone_trust_cert_ref",
    "artifact_sha256",
    "govsec_admissibility_status",
    "govsec_admissibility_decision",
    "govsec_layer",
    "reality_formation_input",
    "ingress_actor_id",
    "ingress_actor_role",
    "operator_review_required",
    "training_pipeline_allowed",
    "allowed_next_gates",
    "notes",
})


class KeystoneIngressError(Exception):
    """Base class for DEP.KEYSTONE ingress gate errors."""


class KeystoneIngressValidationError(KeystoneIngressError):
    """Raised when an ingress record is structurally invalid."""


class KeystoneIngressBlockedError(KeystoneIngressError):
    """Raised when an ingress record is in a terminal blocked state."""


class KeystoneIngressNotAllowedError(KeystoneIngressError):
    """Raised when an ingress record is not cleared for training pipeline entry."""


def load_ingress_record(path) -> dict:
    """Load and parse a DEP.KEYSTONE ingress record from a JSON file."""
    p = Path(path)
    if not p.exists():
        raise KeystoneIngressValidationError(
            f"DEP.KEYSTONE ingress record not found: {p}"
        )
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise KeystoneIngressValidationError(
            f"DEP.KEYSTONE ingress record is not valid JSON: {exc}"
        ) from exc


def validate_ingress_record(record: dict) -> dict:
    """
    Structural validation of a TR-04D ingress record.

    Returns {"valid": True, ...} on success.
    Raises KeystoneIngressValidationError on failure.
    """
    errors = []
    for field in sorted(REQUIRED_FIELDS):
        if field not in record:
            errors.append(f"missing required field: {field!r}")
    if errors:
        raise KeystoneIngressValidationError(
            f"DEP.KEYSTONE ingress validation failed ({len(errors)} error(s)):\n"
            + "\n".join(f"  - {e}" for e in errors)
        )

    govsec_status = record.get("govsec_admissibility_status")
    if govsec_status not in VALID_GOVSEC_ADMISSIBILITY_STATUSES:
        raise KeystoneIngressValidationError(
            f"Invalid govsec_admissibility_status: {govsec_status!r}. "
            f"Valid: {sorted(VALID_GOVSEC_ADMISSIBILITY_STATUSES)}"
        )

    govsec_decision = record.get("govsec_admissibility_decision")
    if govsec_decision not in VALID_GOVSEC_ADMISSIBILITY_DECISIONS:
        raise KeystoneIngressValidationError(
            f"Invalid govsec_admissibility_decision: {govsec_decision!r}. "
            f"Valid: {sorted(VALID_GOVSEC_ADMISSIBILITY_DECISIONS)}"
        )

    dk_status = record.get("dep_keystone_status")
    if dk_status not in VALID_DEP_KEYSTONE_STATUSES:
        raise KeystoneIngressValidationError(
            f"Invalid dep_keystone_status: {dk_status!r}. "
            f"Valid: {sorted(VALID_DEP_KEYSTONE_STATUSES)}"
        )

    layer = record.get("govsec_layer")
    if layer not in VALID_GOVSEC_LAYERS:
        raise KeystoneIngressValidationError(
            f"Invalid govsec_layer: {layer!r}. Valid: {sorted(VALID_GOVSEC_LAYERS)}"
        )

    for gate in record.get("allowed_next_gates", []):
        if gate not in VALID_NEXT_GATES:
            raise KeystoneIngressValidationError(
                f"Invalid entry in allowed_next_gates: {gate!r}. "
                f"Valid: {sorted(VALID_NEXT_GATES)}"
            )

    return {
        "valid": True,
        "dep_keystone_ingress_id": record.get("dep_keystone_ingress_id"),
        "source_id": record.get("source_id"),
        "govsec_admissibility_status": govsec_status,
        "govsec_admissibility_decision": govsec_decision,
        "dep_keystone_status": dk_status,
    }


def assert_training_ingress_allowed(
    record: dict,
    source_id: str = None,
    next_gate: str = None,
) -> dict:
    """
    Assert that this ingress record clears the training pipeline gate.

    Gate order:
      1. GovSec blocked states          → KeystoneIngressBlockedError (terminal)
      2. GovSec pending states          → KeystoneIngressNotAllowedError
      3. GovSec must be approved        → KeystoneIngressNotAllowedError
      4. GovSec accepted_for_clearance  → KeystoneIngressNotAllowedError
      5. DEP.KEYSTONE FAILED            → KeystoneIngressBlockedError (terminal)
      6. DEP.KEYSTONE must be VERIFIED  → KeystoneIngressNotAllowedError
      7. DEP.KEYSTONE trust_score >= 70 → KeystoneIngressNotAllowedError
      8. HAAP DRS escalation check      → KeystoneIngressNotAllowedError
      9. DEP.KEYSTONE evidence refs     → KeystoneIngressNotAllowedError
     10. artifact_sha256 non-empty      → KeystoneIngressNotAllowedError
     11. training_pipeline_allowed      → KeystoneIngressNotAllowedError
     12. source_id match (if given)     → KeystoneIngressNotAllowedError
     13. next_gate in allowed (if given)→ KeystoneIngressNotAllowedError

    Args:
        record:    A TR-04D ingress record dict.
        source_id: If provided, assert the record's source_id matches.
        next_gate: If provided, assert it appears in allowed_next_gates.
    """
    ingress_id    = record.get("dep_keystone_ingress_id", "<unknown>")
    govsec_status = record.get("govsec_admissibility_status", "")
    rec_source    = record.get("source_id", "")

    # 1. GovSec blocked states (terminal)
    if govsec_status in _BLOCKED_STATUSES:
        raise KeystoneIngressBlockedError(
            f"DEP.KEYSTONE ingress {ingress_id!r}: "
            f"govsec_admissibility_status={govsec_status!r}. "
            "Training pipeline entry is permanently blocked."
        )

    # 2. GovSec pending states
    if govsec_status in _PENDING_STATUSES:
        raise KeystoneIngressNotAllowedError(
            f"DEP.KEYSTONE ingress {ingress_id!r}: "
            f"govsec_admissibility_status={govsec_status!r}. "
            "Clearance is not complete."
        )

    # 3. GovSec must be approved
    if govsec_status != "approved":
        raise KeystoneIngressNotAllowedError(
            f"DEP.KEYSTONE ingress {ingress_id!r}: "
            f"govsec_admissibility_status={govsec_status!r}. "
            "Only approved ingress records may enter the training pipeline."
        )

    # 4. GovSec decision
    govsec_decision = record.get("govsec_admissibility_decision", "")
    if govsec_decision != "accepted_for_clearance":
        raise KeystoneIngressNotAllowedError(
            f"DEP.KEYSTONE ingress {ingress_id!r}: "
            f"govsec_admissibility_decision={govsec_decision!r}. "
            "Must be accepted_for_clearance."
        )

    # 5. DEP.KEYSTONE FAILED is a terminal supply-chain failure
    dk_status = record.get("dep_keystone_status")
    if dk_status == "FAILED":
        raise KeystoneIngressBlockedError(
            f"DEP.KEYSTONE ingress {ingress_id!r}: dep_keystone_status=FAILED. "
            "Supply-chain trust check failed. Training pipeline entry blocked."
        )

    # 6. DEP.KEYSTONE must be VERIFIED
    if dk_status != "VERIFIED":
        raise KeystoneIngressNotAllowedError(
            f"DEP.KEYSTONE ingress {ingress_id!r}: "
            f"dep_keystone_status={dk_status!r}. "
            "Must be VERIFIED to enter the training pipeline."
        )

    # 7. DEP.KEYSTONE trust score
    dk_trust_score = record.get("dep_keystone_trust_score")
    if dk_trust_score is None or dk_trust_score < 70:
        raise KeystoneIngressNotAllowedError(
            f"DEP.KEYSTONE ingress {ingress_id!r}: "
            f"dep_keystone_trust_score={dk_trust_score!r}. "
            "Score < 70 requires HAAP DRS escalation. Training pipeline blocked."
        )

    # 8. HAAP DRS escalation flag
    if record.get("dep_keystone_haap_drs_escalation_required") is True:
        raise KeystoneIngressNotAllowedError(
            f"DEP.KEYSTONE ingress {ingress_id!r}: "
            "dep_keystone_haap_drs_escalation_required=true. "
            "HAAP v2.0 DRS escalation required before training pipeline entry."
        )

    # 9. DEP.KEYSTONE evidence refs (fail closed when missing)
    if not record.get("dep_keystone_evidence_sha256_ref", ""):
        raise KeystoneIngressNotAllowedError(
            f"DEP.KEYSTONE ingress {ingress_id!r}: "
            "dep_keystone_evidence_sha256_ref is missing or empty."
        )

    if not record.get("dep_keystone_verification_report_ref", ""):
        raise KeystoneIngressNotAllowedError(
            f"DEP.KEYSTONE ingress {ingress_id!r}: "
            "dep_keystone_verification_report_ref is missing or empty."
        )

    if not record.get("dep_keystone_sbom_ref", ""):
        raise KeystoneIngressNotAllowedError(
            f"DEP.KEYSTONE ingress {ingress_id!r}: "
            "dep_keystone_sbom_ref is missing or empty."
        )

    # 10. Artifact SHA
    if not record.get("artifact_sha256", ""):
        raise KeystoneIngressNotAllowedError(
            f"DEP.KEYSTONE ingress {ingress_id!r}: artifact_sha256 is missing or empty."
        )

    # 11. Training pipeline allowed
    if record.get("training_pipeline_allowed") is not True:
        raise KeystoneIngressNotAllowedError(
            f"DEP.KEYSTONE ingress {ingress_id!r}: training_pipeline_allowed is not true."
        )

    # 12. Source ID match
    if source_id is not None and rec_source != source_id:
        raise KeystoneIngressNotAllowedError(
            f"DEP.KEYSTONE ingress {ingress_id!r}: source_id mismatch — "
            f"record has {rec_source!r}, requested {source_id!r}."
        )

    # 13. Next gate check
    if next_gate is not None:
        allowed = record.get("allowed_next_gates", [])
        if next_gate not in allowed:
            raise KeystoneIngressNotAllowedError(
                f"DEP.KEYSTONE ingress {ingress_id!r}: next_gate={next_gate!r} is not in "
                f"allowed_next_gates={allowed!r}."
            )

    return {
        "cleared":                       True,
        "dep_keystone_ingress_id":       ingress_id,
        "source_id":                     rec_source,
        "govsec_admissibility_status":   govsec_status,
        "govsec_admissibility_decision": govsec_decision,
        "dep_keystone_status":           dk_status,
        "dep_keystone_trust_score":      dk_trust_score,
        "next_gate":                     next_gate,
        "govsec_layer":                  record.get("govsec_layer"),
        "reality_formation_input":       record.get("reality_formation_input"),
    }


def summarize_ingress(record: dict) -> dict:
    """Return an audit-safe summary (excludes raw artifact hashes and evidence refs)."""
    return {
        "dep_keystone_ingress_id":   record.get("dep_keystone_ingress_id"),
        "source_id":                 record.get("source_id"),
        "source_name":               record.get("source_name"),
        "dep_keystone_project_name": record.get("dep_keystone_project_name"),
        "dep_keystone_status":       record.get("dep_keystone_status"),
        "dep_keystone_trust_score":  record.get("dep_keystone_trust_score"),
        "dep_keystone_findings_count": record.get("dep_keystone_findings_count"),
        "dep_keystone_haap_drs_escalation_required":
            record.get("dep_keystone_haap_drs_escalation_required"),
        "govsec_admissibility_status":   record.get("govsec_admissibility_status"),
        "govsec_admissibility_decision": record.get("govsec_admissibility_decision"),
        "govsec_layer":                  record.get("govsec_layer"),
        "reality_formation_input":       record.get("reality_formation_input"),
        "training_pipeline_allowed":     record.get("training_pipeline_allowed"),
        "allowed_next_gates":            record.get("allowed_next_gates", []),
        "ingress_actor_id":              record.get("ingress_actor_id"),
        "ingress_actor_role":            record.get("ingress_actor_role"),
        "operator_review_required":      record.get("operator_review_required"),
    }

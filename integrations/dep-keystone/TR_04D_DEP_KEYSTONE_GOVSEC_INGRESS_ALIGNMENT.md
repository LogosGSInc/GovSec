# TR-04D: Training Ingress Alignment — DEP.KEYSTONE + GovSec V2

**Version**: 1.0.0  
**Status**: Implemented  
**Authority**: LOGOS Governance Systems Inc.  
**Effective Date**: 2026-06-27  
**Produces**: `dep_keystone_ingress.py` — Abigail-side training-ingress gate  
**Corrected**: 2026-06-27 (TR-05A — DEP.KEYSTONE scope clarification)

---

## Recon Result

A comprehensive grep of `training/`, `abigail/`, `governance-spine/`, `agents/`,
and `docs/` for `DEP`, `KEYSTONE`, `Keystone`, `GovSec`, `Layer Zero`,
`admissibility`, `ingress`, `trust certificate`, `sbom`, and related field names
found **no pre-existing callable training-ingress gate**.

`DEPT-*` occurrences were department identifiers only. `GOVMEM_DEPARTMENT_ID`
was an env-var reference, not a gate.

**Result: No pre-existing gate existed. `dep_keystone_ingress.py` was created
as the new narrow TR-04D Abigail-side bridge.**

---

## Architecture: Three Distinct Layers

```
┌─────────────────────────────────────────────────────────┐
│  DEP.KEYSTONE (LogosGSInc/dep.keystone)                 │
│  Standalone LOGOS supply-chain trust product            │
│  Outputs: verification-report.json, evidence.sha256,    │
│           sbom.cdx.json (CycloneDX 1.5), TrustCert     │
│  Metrics: Trust Score (0-100), Status (VERIFIED/FAILED),│
│           Findings count, HAAP DRS escalation flag      │
└──────────────────────┬──────────────────────────────────┘
                       │ Abigail references outputs only.
                       │ Abigail does NOT redefine, vendor,
                       │ or duplicate DEP.KEYSTONE.
┌──────────────────────▼──────────────────────────────────┐
│  GovSec V2 / Layer Zero (Abigail training doctrine)     │
│  Broader training-admissibility policy and lifecycle    │
│  Fields: govsec_admissibility_status/decision,          │
│          govsec_layer, reality_formation_input,         │
│          training_pipeline_allowed, allowed_next_gates  │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│  TR-04D Bridge (dep_keystone_ingress.py)                │
│  Combines DEP.KEYSTONE trust-bundle evidence refs       │
│  with GovSec V2 training-admissibility decisions        │
└──────────────────────┬──────────────────────────────────┘
                       │
        ┌──────────────┼──────────────────────┐
        ▼              ▼                      ▼
  Source Registry  Clearance Ledger   Dataset / Dry-Run / Registry
  (TR-04A)         (TR-04A.4)         (TR-03, TR-04B, TR-05)
  ← separate gate  ← separate gate    ← separate gates
```

**Key boundary**: DEP.KEYSTONE is a standalone LOGOS product. Abigail consumes
its trust-bundle outputs via references. Abigail does not become DEP.KEYSTONE.
Source Registry clearance and Clearance Ledger approval are independent
Abigail-side gates — they are not replaced by DEP.KEYSTONE evidence.

---

## What TR-04D Does

`training/dep_keystone_ingress.py` implements the Abigail-side bridge:

1. Loads and validates TR-04D ingress records (JSON) against `REQUIRED_FIELDS`.
2. Validates GovSec V2 training admissibility:
   - `govsec_admissibility_status=approved`
   - `govsec_admissibility_decision=accepted_for_clearance`
3. Validates DEP.KEYSTONE supply-chain trust:
   - `dep_keystone_status=VERIFIED` (FAILED → terminal block)
   - `dep_keystone_trust_score >= 70` (< 70 → HAAP DRS escalation required → block)
   - `dep_keystone_haap_drs_escalation_required=false` (true → block)
4. Validates DEP.KEYSTONE trust-bundle refs are non-empty:
   - `dep_keystone_verification_report_ref` (→ verification-report.json)
   - `dep_keystone_evidence_sha256_ref` (→ evidence.sha256)
   - `dep_keystone_sbom_ref` (→ sbom.cdx.json)
5. Validates `artifact_sha256`, `training_pipeline_allowed=true`, source identity
   and allowed next gate when provided.

---

## Separation of Concerns

| Concern | Owner | Location |
|---|---|---|
| Supply-chain dependency trust verification | DEP.KEYSTONE (`LogosGSInc/dep.keystone`) | External LOGOS product |
| Training-admissibility doctrine (Layer Zero) | GovSec V2 / Abigail | `dep_keystone_ingress.py` |
| Trust-bundle reference bridging | TR-04D (this module) | `dep_keystone_ingress.py` |
| Source eligibility clearance | TR-04A Source Registry | `source_registry.py` |
| Operator clearance approval | TR-04A Clearance Ledger | `clearance_ledger.py` |
| Synthetic data governance | TR-04A.5, TR-04C | `synthetic_doctrine.py`, `synthetic_review_bridge.py` |
| Dataset immutability | TR-03 | `dataset_builder.py` |
| Dry-run governance | TR-04B | `dry_run_trainer.py` |
| Model artifact lineage | TR-05 | `model_registry.py` |

---

## GovSec V2 Layers

| `govsec_layer` | Meaning |
|---|---|
| `layer_zero_reality_formation` | Artifact shapes Abigail cognition (training data, embeddings) |
| `dep_keystone_supply_chain` | Artifact provenance verified through DEP.KEYSTONE |
| `training_readiness_ingress` | Artifact has passed training-specific admissibility review |

---

## Ingress Record Field Groups

`DEP_KEYSTONE_TRAINING_INGRESS.schema.json` has two groups:

### Group 1: DEP.KEYSTONE Trust-Bundle Fields (references to DEP.KEYSTONE outputs)

| Field | Type | Notes |
|---|---|---|
| `dep_keystone_project_name` | string | e.g., `LogosGSInc/dep.keystone` |
| `dep_keystone_status` | enum | `VERIFIED` or `FAILED` |
| `dep_keystone_trust_score` | number | 0–100; < 70 → HAAP escalation |
| `dep_keystone_findings_count` | integer | Findings from DEP.KEYSTONE scan |
| `dep_keystone_haap_drs_escalation_required` | boolean | DEP.KEYSTONE sets true when score < 70 |
| `dep_keystone_verification_report_ref` | string | Ref to `verification-report.json` |
| `dep_keystone_evidence_sha256_ref` | string | Ref to `evidence.sha256` file |
| `dep_keystone_sbom_ref` | string | Ref to `sbom.cdx.json` |
| `dep_keystone_trust_cert_ref` | string | Ref to TrustCert envelope |

These fields hold **references** to DEP.KEYSTONE output files — not re-computed
hashes or vendored DEP.KEYSTONE logic.

### Group 2: GovSec V2 / Abigail Training-Admissibility Fields

| Field | Type | Notes |
|---|---|---|
| `dep_keystone_ingress_id` | string | Abigail-side record ID (DKI-*) |
| `govsec_admissibility_status` | enum | `approved` required |
| `govsec_admissibility_decision` | enum | `accepted_for_clearance` required |
| `govsec_layer` | enum | see table above |
| `reality_formation_input` | boolean | `true` for training data |
| `artifact_sha256` | string | SHA-256 of artifact being cleared |
| `training_pipeline_allowed` | boolean | `true` for approved records |
| `allowed_next_gates` | array | Pipeline gates this source may enter |
| `ingress_actor_id` | string | Reviewer identifier |
| `operator_review_required` | boolean | `true` for training data |

---

## Public API

```python
from training.dep_keystone_ingress import (
    load_ingress_record,
    validate_ingress_record,
    assert_training_ingress_allowed,
    summarize_ingress,
    KeystoneIngressBlockedError,    # terminal: FAILED or GovSec blocked/rejected/archived
    KeystoneIngressNotAllowedError, # not cleared: pending, low trust_score, missing refs
    KeystoneIngressValidationError, # structurally invalid record
)

record = load_ingress_record("/path/to/dep_keystone_ingress.json")
validate_ingress_record(record)

clearance = assert_training_ingress_allowed(
    record,
    source_id="L1-001",              # optional: must match record.source_id
    next_gate="tr05_model_registry", # optional: must be in allowed_next_gates
)
# clearance = {
#     "cleared": True,
#     "dep_keystone_status": "VERIFIED",
#     "dep_keystone_trust_score": 95,
#     "govsec_admissibility_status": "approved",
#     "govsec_admissibility_decision": "accepted_for_clearance",
#     ...
# }
```

---

## Pipeline Position

```
DEP.KEYSTONE / GovSec ingress  (TR-04D — dep_keystone_ingress.py)
  ↓
TR-04A Source Registry          (source_registry.py)
  ↓
TR-04A Clearance Ledger         (clearance_ledger.py)
  ↓
TR-04A.5 Synthetic Doctrine     (synthetic_doctrine.py)
  ↓
TR-04C Synthetic Review Bridge  (synthetic_review_bridge.py)
  ↓
TR-03 Immutable Dataset Builder (dataset_builder.py)
  ↓
TR-04B Dry-Run Trainer          (dry_run_trainer.py)
  ↓
TR-05 Model Registry + Lineage  (model_registry.py)
```

TR-04D is optional at individual pipeline stages. Hard mandatory enforcement at
source registry level is a future migration. The `dep_keystone_ingress_id` field
is optional in `SOURCE_REGISTRY.schema.json` — new sources should populate it.

---

## Governance Attestation

No real training occurred in TR-04D. No model weights were created. No Store 1
writes occurred. No external calls were made. TR-05 was not started here.

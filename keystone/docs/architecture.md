# DEP.KEYSTONE Architecture

## Core Definitions

**Trust Certificate Bundle**
The three-artifact output of a single `dep-keystone verify` run:
- `verification-report.json` — governance and risk artifact
- `evidence.sha256` — deterministic hash attestation anchor
- `sbom.cdx.json` — CycloneDX 1.5 software bill of materials

**Trust Score**
A severity-weighted measure (0–100) of supply chain integrity and compliance risk.
Formula: `100 - sum(severity_weights)` floored at 0.
Weights: critical=40, high=20, medium=10, low=5, info=0.

**SBOM (Software Bill of Materials)**
A standardized machine-readable inventory of every dependency.
CycloneDX 1.5 — NTIA-endorsed, required for US federal procurement.

**Verification Report**
JSON artifact containing trust score, findings with severity and remediation,
manifest hash, and TrustCert envelope. Consumed by CI/CD gates and compliance teams.

**Evidence Hash**
Deterministic SHA-256 of the complete dependency graph evidence payload.
Same graph always produces the same hash — enabling reproducible attestation.

**TrustCert**
Cryptographic attestation envelope inside every report.
Contains: manifest_hash_sha256, evidence_hash_sha256, generated_at, scheme (HAAP-SHA256).
Phase 2: Sigstore/cosign signing for full SLSA Level 2+ provenance.

## Architecture Layers

```
Input (lockfile)
  └── Parser Layer         parsers/requirements_txt.py
        └── Dependency     Canonical immutable record (models.py)
               └── Hashing Layer       manifest_hash_sha256() (hashing.py)
                      └── Findings Engine    generate_findings() (report.py)
                             └── Report Builder   build_verification_report()
                                    └── Trust Bundle Output
                                           ├── verification-report.json
                                           ├── evidence.sha256
                                           └── sbom.cdx.json
```

## Signal Rules (Phase 1)

| Code    | Severity | Signal                                      |
|---------|----------|---------------------------------------------|
| DEP-001 | medium   | Unpinned version (unbounded)                |
| DEP-002 | low      | Loose specifier (>=, >, ~=, !=)             |
| DEP-003 | high     | Duplicate package name / version conflict   |
| DEP-004 | medium   | Risky package name pattern                  |
| DEP-005 | high     | Direct dependency + unpinned                |
| DEP-006 | critical | Known typosquat pattern detected            |

## Compliance Mapping

| Standard     | DEP.KEYSTONE Coverage                           |
|--------------|-------------------------------------------------|
| NTIA SBOM    | CycloneDX 1.5 output (sbom.cdx.json)           |
| SLSA Level 1 | evidence.sha256 hash attestation               |
| NIST AI RMF  | Supply chain risk identification (GOVERN 1.1)  |
| EO 14028     | Software supply chain security artifacts        |
| SOC 2 Type II| Dependency audit trail + verification report   |

## LOGOS Governance Stack Integration

DEP.KEYSTONE operates at the supply chain trust layer.
Its trust_score feeds into HAAP v2.0 Dynamic Risk Score (DRS).
A trust_score < 70 should trigger HAAP Layer 3 JIT Authorization
before any AI system deployment is approved.

## Phase 2 Roadmap

- Sigstore/cosign signing of evidence.sha256
- npm package-lock.json parser
- Cargo.lock parser
- OSV vulnerability database integration (live CVE signals)
- GitHub Actions integration
- Trust score threshold enforcement in CI pipelines

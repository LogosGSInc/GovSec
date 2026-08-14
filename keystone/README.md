# DEP.KEYSTONE

**Deterministic dependency verification and supply chain attestation for AI systems.**

DEP.KEYSTONE verifies software dependencies, assigns a severity-weighted Trust Score, and emits a three-file **Trust Certificate Bundle** for audit, procurement, and CI/CD enforcement.

> **Trust Score:** A severity-weighted measure (0–100) of supply chain integrity and compliance risk.

Built by **[LOGOS Governance Systems Inc.](https://github.com/LogosGSInc)**

---

## Why it exists

AI systems inherit risk from their dependency graph long before model behavior is evaluated.

DEP.KEYSTONE gives teams a deterministic way to verify that supply-chain layer before deployment — emitting three machine-readable artifacts every time:

- `verification-report.json`
- `evidence.sha256`
- `sbom.cdx.json`

The result is a verifiable trust bundle that supports audit, procurement, and CI/CD decision-making.

---

## Demo

    dep-keystone verify requirements.txt --project-name my-ai-service

**Risky graph — before pinning:**

    DEP.KEYSTONE  Trust Bundle
    Project      my-ai-service
    Dependencies 5
    Trust Score  65/100
    Status       FAILED
    Findings     3
      [MEDIUM  ] DEP-001 — boto3 has no pinned version
      [HIGH    ] DEP-005 — boto3 is a direct dependency with no version pin
      [LOW     ] DEP-002 — click@8.1.7 uses loose specifier '>='
    Output       ./out/

**Clean graph — after pinning:**

    DEP.KEYSTONE  Trust Bundle
    Project      my-ai-service
    Dependencies 5
    Trust Score  100/100
    Status       VERIFIED
    Output       ./out/

Same project. Better dependency hygiene. Materially better deployability.

---

## Trust Certificate Bundle

Every `dep-keystone verify` run emits three artifacts:

| Artifact | Format | Purpose |
|---|---|---|
| `verification-report.json` | JSON | Trust score, findings, severity, remediation, TrustCert envelope |
| `evidence.sha256` | SHA-256 hex | Deterministic attestation anchor — same graph = same hash, always |
| `sbom.cdx.json` | CycloneDX 1.5 | Machine-readable software bill of materials |

---

## Trust Score

| Severity | Weight |
|---|---:|
| critical | -40 |
| high | -20 |
| medium | -10 |
| low | -5 |
| info | 0 |

Trust Score = 100 minus sum of weights, floored at 0. A fully pinned clean graph scores 100/100 VERIFIED.

---

## Signal Rules

| Code | Severity | Signal |
|---|---|---|
| DEP-001 | medium | Unpinned version |
| DEP-002 | low | Loose specifier |
| DEP-003 | high | Duplicate package / version conflict |
| DEP-004 | medium | Risky package-name pattern |
| DEP-005 | high | Direct dependency with no version pin |
| DEP-006 | critical | Known typosquat pattern detected |

---

## Install

Python 3.11+ required.

    git clone https://github.com/LogosGSInc/dep.keystone.git
    cd dep.keystone
    python -m venv .venv && source .venv/bin/activate
    pip install -e .
    pip install pytest && pytest tests/ -v
    # 31 passed in 0.06s

---

## Usage

    dep-keystone verify requirements.txt --project-name my-project
    dep-keystone verify requirements.txt --project-name my-project --output-dir reports/
    ls out/
    # evidence.sha256  sbom.cdx.json  verification-report.json

---

## Standards Alignment

| Framework | Coverage |
|---|---|
| NTIA SBOM Minimum Elements | CycloneDX 1.5 machine-readable output |
| EO 14028 | Software supply-chain security artifact expectations |
| NIST AI RMF GOVERN 1.1 | Supply-chain risk identification and scoring |
| SLSA Level 1 | evidence.sha256 deterministic hash attestation |
| SOC 2 Type II | Dependency audit trail and structured verification report |

---

## Architecture

    Input (lockfile)
      Parser              parsers/requirements_txt.py
      Dependency model    models.py — immutable, canonical, frozen
      Hashing layer       hashing.py — order-independent SHA-256
      Findings engine     report.py — 6 signal rules, severity-weighted
      Output layer
        verification-report.json
        evidence.sha256
        sbom.cdx.json  — CycloneDX 1.5

Key properties:
- Immutable frozen Dependency objects after parse
- Order-independent manifest hashing — same graph, same hash, always
- Project-scoped evidence hashing — no cross-project hash collisions
- TrustCert embedded in every report

---

## Roadmap

- npm package-lock.json parser
- Cargo.lock parser
- OSV vulnerability database — live CVE signals per dependency
- GitHub Actions CI enforcement — fail PRs below trust threshold
- Sigstore/cosign signing of evidence.sha256 (SLSA Level 2+)
- HAAP v2.0 Dynamic Risk Score integration

---

## About

DEP.KEYSTONE is the supply-chain trust layer of the LOGOS Governance Systems platform.

Its Trust Score feeds into the HAAP v2.0 Dynamic Risk Score (DRS). A trust_score below 70 triggers HAAP Layer 3 JIT Authorization before any AI system deployment is approved.

LOGOS Governance Systems Inc. builds deterministic governance infrastructure for AI systems — verifiable, auditable, and defensible at enterprise scale.

---

## License

Proprietary — Copyright 2026 LOGOS Governance Systems Inc. All rights reserved.

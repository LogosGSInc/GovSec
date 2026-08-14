from __future__ import annotations

import json
from pathlib import Path
from .hashing import evidence_hash_sha256, manifest_hash_sha256, write_evidence_sha256
from .models import Dependency, TrustCert, VerificationFinding, VerificationReport, utc_now_iso
from .sbom import write_sbom_cdx

SEVERITY_WEIGHTS = {"critical": 40, "high": 20, "medium": 10, "low": 5, "info": 0}

RISKY_PACKAGE_PATTERNS = {
    "pickle", "backdoor", "cryptominer", "keylogger", "rootkit",
}

KNOWN_TYPOSQUATS = {
    "reqeusts", "requets", "reqests", "flaks", "djnago",
    "nump", "pandes", "scikit-lern", "tensor-flow", "boto",
}


def calculate_trust_score(findings: list[VerificationFinding]) -> int:
    if not findings:
        return 100
    return max(0, 100 - sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings))


def derive_status(findings: list[VerificationFinding]) -> str:
    if not findings:
        return "verified"
    severities = {f.severity for f in findings}
    if "critical" in severities or "high" in severities:
        return "failed"
    if "medium" in severities or "low" in severities:
        return "warning"
    return "verified"


def generate_findings(dependencies: list[Dependency]) -> list[VerificationFinding]:
    findings: list[VerificationFinding] = []
    seen_names: dict[str, list[Dependency]] = {}

    for dep in dependencies:
        seen_names.setdefault(dep.name, []).append(dep)

        # DEP-001: Unpinned version
        if dep.version == "unbounded":
            findings.append(VerificationFinding(
                code="DEP-001",
                message=f"{dep.name} has no pinned version — unpinned dependencies weaken the trust certificate.",
                severity="medium",
                dependency=dep.canonical_identity(),
                remediation=f"Pin {dep.name} to an exact version, e.g. {dep.name}==<version>",
            ))

        # DEP-002: Loose specifier
        elif dep.metadata.get("specifier") in (">", ">=", "!=", "~="):
            findings.append(VerificationFinding(
                code="DEP-002",
                message=f"{dep.name}@{dep.version} uses loose specifier '{dep.metadata['specifier']}' — exact pin preferred.",
                severity="low",
                dependency=dep.canonical_identity(),
                remediation=f"Use == to pin {dep.name} exactly.",
            ))

        # DEP-004: Risky package name pattern
        for pattern in RISKY_PACKAGE_PATTERNS:
            if pattern in dep.name.lower():
                findings.append(VerificationFinding(
                    code="DEP-004",
                    message=f"{dep.name} matches risky package pattern '{pattern}' — manual review required.",
                    severity="medium",
                    dependency=dep.canonical_identity(),
                    remediation="Verify this is a trusted, intended dependency.",
                ))
                break

        # DEP-005: Direct + unpinned = elevated risk
        if dep.version == "unbounded" and dep.direct:
            findings.append(VerificationFinding(
                code="DEP-005",
                message=f"{dep.name} is a direct dependency with no version pin — highest supply chain exposure.",
                severity="high",
                dependency=dep.canonical_identity(),
                remediation=f"Direct dependencies must be pinned. Add {dep.name}==<version> immediately.",
            ))

        # DEP-006: Known typosquat
        if dep.name.lower() in KNOWN_TYPOSQUATS:
            findings.append(VerificationFinding(
                code="DEP-006",
                message=f"{dep.name} matches a known typosquat pattern — possible supply chain attack.",
                severity="critical",
                dependency=dep.canonical_identity(),
                remediation=f"Remove {dep.name} immediately and verify your intended dependency.",
            ))

    # DEP-003: Duplicate package name
    for name, deps_list in seen_names.items():
        if len(deps_list) > 1:
            versions = ", ".join(d.version for d in deps_list)
            findings.append(VerificationFinding(
                code="DEP-003",
                message=f"{name} appears {len(deps_list)} times with versions: {versions} — version conflict risk.",
                severity="high",
                dependency=f"pypi:{name}",
                remediation=f"Consolidate {name} to a single pinned version.",
            ))

    return findings


def build_verification_report(
    *,
    project_name: str,
    source_file: str,
    dependencies: list[Dependency],
    findings: list[VerificationFinding] | None = None,
    tool_version: str = "0.1.0",
) -> VerificationReport:
    all_findings = (findings or []) + generate_findings(dependencies)
    generated_at = utc_now_iso()
    manifest_hash = manifest_hash_sha256(dependencies)
    evidence_hash = evidence_hash_sha256(
        dependencies, project_name=project_name, source_file=source_file
    )
    trust_cert = TrustCert(
        manifest_hash_sha256=manifest_hash,
        evidence_hash_sha256=evidence_hash,
        generated_at=generated_at,
    )
    return VerificationReport(
        project_name=project_name,
        source_file=source_file,
        status=derive_status(all_findings),
        generated_at=generated_at,
        dependency_count=len(dependencies),
        manifest_hash_sha256=manifest_hash,
        findings=all_findings,
        dependencies=dependencies,
        trust_score=calculate_trust_score(all_findings),
        trust_cert=trust_cert,
        tool_name="dep-keystone",
        tool_version=tool_version,
    )


def write_trust_bundle_artifacts(
    *,
    output_dir: str | Path,
    project_name: str,
    source_file: str,
    dependencies: list[Dependency],
    findings: list[VerificationFinding] | None = None,
    tool_version: str = "0.1.0",
) -> VerificationReport:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    report = build_verification_report(
        project_name=project_name,
        source_file=source_file,
        dependencies=dependencies,
        findings=findings,
        tool_version=tool_version,
    )

    # Artifact 1: verification-report.json
    (out_dir / "verification-report.json").write_text(
        json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8"
    )

    # Artifact 2: evidence.sha256
    write_evidence_sha256(
        out_dir / "evidence.sha256",
        dependencies,
        project_name=project_name,
        source_file=source_file,
    )

    # Artifact 3: sbom.cdx.json
    write_sbom_cdx(
        out_dir / "sbom.cdx.json",
        dependencies,
        project_name=project_name,
        manifest_hash=report.manifest_hash_sha256,
    )

    return report

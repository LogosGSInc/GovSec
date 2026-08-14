from __future__ import annotations
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

Ecosystem = Literal["pypi", "npm", "cargo", "generic"]
VerificationStatus = Literal["verified", "warning", "failed", "unknown"]

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

@dataclass(slots=True, frozen=True)
class Dependency:
    name: str
    version: str
    ecosystem: Ecosystem
    source_file: str
    hash_sha256: str | None = None
    license_id: str | None = None
    purl: str | None = None
    direct: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise ValueError("Dependency.name must be non-empty")
        if not self.version or not self.version.strip():
            raise ValueError("Dependency.version must be non-empty")
        if not self.source_file or not self.source_file.strip():
            raise ValueError("Dependency.source_file must be non-empty")

    def canonical_identity(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(slots=True, frozen=True)
class VerificationFinding:
    code: str
    message: str
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    dependency: str | None = None
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(slots=True, frozen=True)
class TrustCert:
    manifest_hash_sha256: str
    evidence_hash_sha256: str
    generated_at: str
    scheme: str = "HAAP-SHA256"
    bundle_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(slots=True, frozen=True)
class VerificationReport:
    project_name: str
    source_file: str
    status: VerificationStatus
    generated_at: str
    dependency_count: int
    manifest_hash_sha256: str
    findings: list[VerificationFinding] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    trust_score: int | None = None
    trust_cert: TrustCert | None = None
    tool_name: str = "dep-keystone"
    tool_version: str = "0.1.0"

    def __post_init__(self) -> None:
        if self.trust_score is not None and not (0 <= self.trust_score <= 100):
            raise ValueError("trust_score must be between 0 and 100")

    def to_dict(self, include_dependencies: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "project_name": self.project_name,
            "source_file": self.source_file,
            "status": self.status,
            "generated_at": self.generated_at,
            "dependency_count": self.dependency_count,
            "manifest_hash_sha256": self.manifest_hash_sha256,
            "findings": [f.to_dict() for f in self.findings],
            "trust_score": self.trust_score,
            "trust_cert": self.trust_cert.to_dict() if self.trust_cert else None,
            "tool": {"name": self.tool_name, "version": self.tool_version},
        }
        if include_dependencies:
            data["dependencies"] = [d.to_dict() for d in self.dependencies]
        return data

@dataclass(slots=True, frozen=True)
class SBOMComponent:
    name: str
    version: str
    purl: str
    type: str = "library"
    bom_ref: str | None = None
    hashes: list[dict[str, str]] = field(default_factory=list)
    licenses: list[dict[str, Any]] = field(default_factory=list)
    properties: list[dict[str, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.name.strip(): raise ValueError("SBOMComponent.name must be non-empty")
        if not self.version.strip(): raise ValueError("SBOMComponent.version must be non-empty")
        if not self.purl.strip(): raise ValueError("SBOMComponent.purl must be non-empty")

    def to_cyclonedx(self) -> dict[str, Any]:
        component: dict[str, Any] = {
            "type": self.type, "name": self.name,
            "version": self.version, "purl": self.purl,
            "bom-ref": self.bom_ref or self.purl,
        }
        if self.hashes: component["hashes"] = self.hashes
        if self.licenses: component["licenses"] = self.licenses
        if self.properties: component["properties"] = self.properties
        return component

def build_purl(dep: Dependency) -> str:
    purl_type = {"pypi":"pypi","npm":"npm","cargo":"cargo","generic":"generic"}.get(dep.ecosystem,"generic")
    return f"pkg:{purl_type}/{dep.name}@{dep.version}"

def dependency_to_sbom_component(dep: Dependency) -> SBOMComponent:
    purl = dep.purl or build_purl(dep)
    hashes = [{"alg": "SHA-256", "content": dep.hash_sha256}] if dep.hash_sha256 else []
    licenses = [{"license": {"id": dep.license_id}}] if dep.license_id else []
    properties = [
        {"name": "dep-keystone:ecosystem", "value": dep.ecosystem},
        {"name": "dep-keystone:source_file", "value": dep.source_file},
        {"name": "dep-keystone:direct", "value": str(dep.direct).lower()},
    ]
    return SBOMComponent(name=dep.name, version=dep.version, purl=purl,
                         hashes=hashes, licenses=licenses, properties=properties)

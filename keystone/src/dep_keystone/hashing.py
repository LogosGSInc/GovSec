from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any, Iterable
from .models import Dependency

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_text(text: str, encoding: str = "utf-8") -> str:
    return sha256_bytes(text.encode(encoding))

def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    file_path = Path(path)
    hasher = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def dependency_fingerprint(dep: Dependency) -> str:
    payload = {"name": dep.name, "version": dep.version, "ecosystem": dep.ecosystem,
               "source_file": dep.source_file, "license_id": dep.license_id,
               "purl": dep.purl, "direct": dep.direct, "metadata": dep.metadata}
    return sha256_text(canonical_json(payload))

def normalize_dependencies_for_hash(dependencies: Iterable[Dependency]) -> list[dict[str, Any]]:
    rows = []
    for dep in dependencies:
        rows.append({"id": dep.canonical_identity(), "name": dep.name, "version": dep.version,
                     "ecosystem": dep.ecosystem, "source_file": dep.source_file,
                     "license_id": dep.license_id, "purl": dep.purl, "direct": dep.direct,
                     "metadata": dep.metadata, "fingerprint_sha256": dependency_fingerprint(dep)})
    rows.sort(key=lambda x: (x["ecosystem"], x["name"].lower(), x["version"], x["source_file"]))
    return rows

def manifest_hash_sha256(dependencies: Iterable[Dependency]) -> str:
    return sha256_text(canonical_json(normalize_dependencies_for_hash(dependencies)))

def evidence_payload(dependencies: Iterable[Dependency], *, project_name: str, source_file: str) -> dict[str, Any]:
    normalized = normalize_dependencies_for_hash(dependencies)
    return {"project_name": project_name, "source_file": source_file,
            "manifest_hash_sha256": sha256_text(canonical_json(normalized)),
            "dependency_count": len(normalized), "dependencies": normalized}

def evidence_hash_sha256(dependencies: Iterable[Dependency], *, project_name: str, source_file: str) -> str:
    return sha256_text(canonical_json(evidence_payload(dependencies, project_name=project_name, source_file=source_file)))

def write_evidence_sha256(output_path: str | Path, dependencies: Iterable[Dependency],
                          *, project_name: str, source_file: str) -> str:
    digest = evidence_hash_sha256(dependencies, project_name=project_name, source_file=source_file)
    Path(output_path).write_text(f"{digest}\n", encoding="utf-8")
    return digest

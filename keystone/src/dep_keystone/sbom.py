from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Dependency, dependency_to_sbom_component


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def build_cyclonedx_sbom(
    dependencies: list[Dependency],
    *,
    project_name: str,
    project_version: str = "0.0.0",
    manifest_hash: str | None = None,
) -> dict[str, Any]:
    serial_number = f"urn:uuid:{uuid.uuid4()}"
    components = [dependency_to_sbom_component(dep).to_cyclonedx() for dep in dependencies]
    metadata_properties: list[dict[str, str]] = [
        {"name": "dep-keystone:tool", "value": "dep-keystone"},
        {"name": "dep-keystone:tool-version", "value": "0.1.0"},
    ]
    if manifest_hash:
        metadata_properties.append(
            {"name": "dep-keystone:manifest-hash-sha256", "value": manifest_hash}
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": _utc_timestamp(),
            "tools": [{"vendor": "LOGOS Governance Systems Inc.", "name": "dep-keystone", "version": "0.1.0"}],
            "component": {
                "type": "application",
                "name": project_name,
                "version": project_version,
                "bom-ref": f"pkg:generic/{project_name}@{project_version}",
            },
            "properties": metadata_properties,
        },
        "components": components,
    }


def write_sbom_cdx(
    output_path: str | Path,
    dependencies: list[Dependency],
    *,
    project_name: str,
    project_version: str = "0.0.0",
    manifest_hash: str | None = None,
) -> dict[str, Any]:
    sbom = build_cyclonedx_sbom(
        dependencies,
        project_name=project_name,
        project_version=project_version,
        manifest_hash=manifest_hash,
    )
    Path(output_path).write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
    return sbom

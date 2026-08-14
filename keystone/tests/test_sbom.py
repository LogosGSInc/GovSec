from __future__ import annotations
from pathlib import Path
import json
from dep_keystone.models import Dependency
from dep_keystone.sbom import build_cyclonedx_sbom, write_sbom_cdx

def _dep(name: str, version: str = "1.0.0") -> Dependency:
    return Dependency(name=name, version=version, ecosystem="pypi", source_file="requirements.txt")

def test_sbom_format_and_spec_version():
    sbom = build_cyclonedx_sbom([_dep("requests", "2.32.3")], project_name="test-project")
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"

def test_sbom_component_count():
    deps = [_dep("requests"), _dep("flask"), _dep("click")]
    assert len(build_cyclonedx_sbom(deps, project_name="test-project")["components"]) == 3

def test_sbom_purl_format():
    sbom = build_cyclonedx_sbom([_dep("requests", "2.32.3")], project_name="test-project")
    assert sbom["components"][0]["purl"] == "pkg:pypi/requests@2.32.3"

def test_sbom_metadata_tool():
    tool = build_cyclonedx_sbom([_dep("flask")], project_name="test-project")["metadata"]["tools"][0]
    assert tool["name"] == "dep-keystone"
    assert tool["vendor"] == "LOGOS Governance Systems Inc."

def test_sbom_serial_number_is_urn_uuid():
    assert build_cyclonedx_sbom([_dep("flask")], project_name="test-project")["serialNumber"].startswith("urn:uuid:")

def test_sbom_manifest_hash_in_properties():
    sbom = build_cyclonedx_sbom([_dep("flask")], project_name="test-project", manifest_hash="abc123")
    props = {p["name"]: p["value"] for p in sbom["metadata"]["properties"]}
    assert props["dep-keystone:manifest-hash-sha256"] == "abc123"

def test_write_sbom_cdx_creates_file(tmp_path: Path):
    out = tmp_path / "sbom.cdx.json"
    write_sbom_cdx(out, [_dep("requests", "2.32.3")], project_name="logos-test")
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["bomFormat"] == "CycloneDX"
    assert len(data["components"]) == 1

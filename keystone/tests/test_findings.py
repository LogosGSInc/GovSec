from __future__ import annotations
from dep_keystone.models import Dependency
from dep_keystone.report import generate_findings, calculate_trust_score, derive_status


def _dep(name: str, version: str = "1.0.0", specifier: str | None = "==", direct: bool = True) -> Dependency:
    return Dependency(
        name=name, version=version, ecosystem="pypi",
        source_file="requirements.txt", direct=direct,
        metadata={"specifier": specifier, "marker": None, "raw_line": f"{name}{specifier or ''}{version}"},
    )


def test_unpinned_generates_dep001():
    dep = _dep("boto3", version="unbounded", specifier=None)
    findings = generate_findings([dep])
    codes = [f.code for f in findings]
    assert "DEP-001" in codes


def test_unpinned_direct_generates_dep005():
    dep = _dep("boto3", version="unbounded", specifier=None, direct=True)
    findings = generate_findings([dep])
    codes = [f.code for f in findings]
    assert "DEP-005" in codes


def test_loose_specifier_generates_dep002():
    dep = _dep("click", version="8.1.7", specifier=">=")
    findings = generate_findings([dep])
    assert any(f.code == "DEP-002" for f in findings)


def test_duplicate_generates_dep003():
    deps = [_dep("requests", "2.31.0"), _dep("requests", "2.32.3")]
    findings = generate_findings(deps)
    assert any(f.code == "DEP-003" for f in findings)


def test_typosquat_generates_dep006():
    dep = _dep("reqeusts", "2.32.3")
    findings = generate_findings([dep])
    assert any(f.code == "DEP-006" and f.severity == "critical" for f in findings)


def test_clean_deps_no_findings():
    deps = [_dep("requests", "2.32.3"), _dep("flask", "3.0.0"), _dep("click", "8.1.7")]
    assert generate_findings(deps) == []


def test_clean_deps_score_100():
    deps = [_dep("requests", "2.32.3"), _dep("flask", "3.0.0")]
    assert calculate_trust_score(generate_findings(deps)) == 100


def test_status_verified_on_clean():
    assert derive_status([]) == "verified"

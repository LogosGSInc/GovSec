from dep_keystone.models import Dependency, VerificationFinding
from dep_keystone.report import calculate_trust_score, derive_status, build_verification_report

def _dep(name):
    return Dependency(name=name, version="1.0.0", ecosystem="pypi", source_file="requirements.txt")

def test_no_findings_score_100():
    assert calculate_trust_score([]) == 100

def test_critical_finding_heavy_penalty():
    f = VerificationFinding(code="X-001", message="critical issue", severity="critical")
    assert calculate_trust_score([f]) == 60

def test_score_floors_at_zero():
    findings = [VerificationFinding(code=f"X-{i}", message="x", severity="critical") for i in range(10)]
    assert calculate_trust_score(findings) == 0

def test_derive_status_verified():
    assert derive_status([]) == "verified"

def test_derive_status_failed_on_high():
    assert derive_status([VerificationFinding(code="X", message="x", severity="high")]) == "failed"

def test_build_report_trust_cert_present():
    deps = [_dep("requests"), _dep("click")]
    report = build_verification_report(project_name="test", source_file="requirements.txt", dependencies=deps)
    assert report.trust_cert is not None
    assert len(report.trust_cert.manifest_hash_sha256) == 64
    assert 0 <= report.trust_score <= 100

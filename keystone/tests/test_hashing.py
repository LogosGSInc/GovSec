from dep_keystone.models import Dependency
from dep_keystone.hashing import dependency_fingerprint, manifest_hash_sha256, evidence_hash_sha256, sha256_text

def _dep(name, version="1.0.0"):
    return Dependency(name=name, version=version, ecosystem="pypi", source_file="requirements.txt")

def test_fingerprint_is_deterministic():
    dep = _dep("requests", "2.32.3")
    assert dependency_fingerprint(dep) == dependency_fingerprint(dep)

def test_manifest_hash_is_order_independent():
    a, b = _dep("alpha"), _dep("beta")
    assert manifest_hash_sha256([a, b]) == manifest_hash_sha256([b, a])

def test_manifest_hash_changes_with_content():
    assert manifest_hash_sha256([_dep("requests","2.31.0")]) != manifest_hash_sha256([_dep("requests","2.32.3")])

def test_evidence_hash_includes_project_name():
    dep = _dep("flask")
    h1 = evidence_hash_sha256([dep], project_name="proj-a", source_file="requirements.txt")
    h2 = evidence_hash_sha256([dep], project_name="proj-b", source_file="requirements.txt")
    assert h1 != h2

def test_sha256_text_is_hex_64_chars():
    digest = sha256_text("hello")
    assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)

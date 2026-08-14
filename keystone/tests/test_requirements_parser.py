from pathlib import Path
from dep_keystone.parsers.requirements_txt import parse_requirements_txt

def test_parse_emits_dependency_objects(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.32.3\nclick>=8.1.7\n# comment\nnumpy==1.26.4 ; python_version >= '3.10'\n")
    deps = parse_requirements_txt(req)
    assert len(deps) == 3
    assert all(d.ecosystem == "pypi" for d in deps)

def test_canonical_identity_format(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("flask==3.0.0\n")
    assert parse_requirements_txt(req)[0].canonical_identity() == "pypi:flask@3.0.0"

def test_unpinned_returns_unbounded(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("boto3\n")
    assert parse_requirements_txt(req)[0].version == "unbounded"

def test_skips_comments_and_blank_lines(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("\n# comment\n   \nrequests==2.31.0\n")
    assert len(parse_requirements_txt(req)) == 1

def test_normalizes_package_name(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("My_Package==1.0.0\n")
    assert parse_requirements_txt(req)[0].name == "my-package"

from __future__ import annotations
import re
from pathlib import Path
from dep_keystone.models import Dependency

_RE = re.compile(r"""
    ^\s*(?P<name>[A-Za-z0-9_.-]+)\s*
    (?:(?P<op>==|>=|<=|!=|~=|>|<)\s*(?P<version>[^\s;#]+))?
    \s*(?P<marker>;[^\#]+)?\s*(?:\#.*)?$""", re.VERBOSE)

def normalize_package_name(name: str) -> str:
    return name.strip().lower().replace("_", "-")

def parse_requirements_txt(path: str | Path) -> list[Dependency]:
    file_path = Path(path)
    deps = []
    for raw_line in file_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"): continue
        if line.startswith(("-r ", "--requirement ", "-e ", "--editable ")): continue
        if "://" in line or line.startswith(("git+", "svn+", "hg+", "bzr+")): continue
        m = _RE.match(line)
        if not m: continue
        deps.append(Dependency(
            name=normalize_package_name(m.group("name")),
            version=m.group("version") or "unbounded",
            ecosystem="pypi", source_file=str(file_path), direct=True,
            metadata={"specifier": m.group("op") or None,
                      "marker": (m.group("marker") or "").strip() or None,
                      "raw_line": raw_line}))
    deps.sort(key=lambda d: (d.name.lower(), d.version, d.source_file))
    return deps

"""Point the published install hooks at one full commit.

Run on every push to main. The commit that pushed is the action people should
run. This rewrites the install hooks to that SHA and pushes a follow-up commit.
The follow-up commit does not run this again.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

SKIP = {".git", ".pytest_cache", "__pycache__", "out"}
_SHA = re.compile(r"^[0-9a-f]{40}$")
_RELEASE = re.compile(r"^v(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){0,3}(?:-[0-9A-Za-z.-]+)?$")


def rewrite(root: Path, new: str) -> str | None:
    if not _SHA.fullmatch(new):
        raise SystemExit("NEW_SHA must be a 40-character commit SHA")
    install_py = root / "pathfinder" / "install.py"
    text = install_py.read_text(encoding="utf-8")
    found = re.search(r'PUBLIC_REF = "([^"]+)"', text)
    if not found:
        raise SystemExit("PUBLIC_REF is missing")
    old = found.group(1)
    if _RELEASE.fullmatch(old):
        return None
    if not _SHA.fullmatch(old):
        raise SystemExit("PUBLIC_REF is not a full commit SHA or a release tag")
    if old == new:
        return None
    for path in root.rglob("*"):
        if not path.is_file() or any(part in SKIP for part in path.parts):
            continue
        if path.suffix.lower() not in {".py", ".yml", ".yaml", ".md"}:
            continue
        current = path.read_text(encoding="utf-8")
        if old not in current:
            continue
        path.write_text(current.replace(old, new), encoding="utf-8", newline="")
    return old


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    rewrite(root, os.environ["NEW_SHA"])


if __name__ == "__main__":
    main()

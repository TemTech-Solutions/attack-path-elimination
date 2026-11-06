"""Decide which GitHub Action refs are allowed to run the scan."""

from __future__ import annotations

import re

_SHA = re.compile(r"^[0-9a-f]{40}$")
_RELEASE = re.compile(r"^v(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){0,2}(?:-[0-9A-Za-z.-]+)?$")


def ref_is_allowed(ref: str) -> bool:
    """A Marketplace release tag or a full commit SHA may run.

    A branch name such as ``main`` is refused. GitHub Marketplace installs
    the latest version as a release tag, for example ``v1.0.2``.
    """
    text = (ref or "").strip()
    if text.startswith("refs/tags/"):
        text = text[len("refs/tags/") :]
    return _SHA.fullmatch(text) is not None or _RELEASE.fullmatch(text) is not None

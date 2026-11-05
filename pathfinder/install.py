"""Drop a CI hook into another repository.

The hook is the workflow published by the public platform repository. GitHub
or GitLab checks the application out on the runner and downloads the analyzer
from that public repository. The application is not copied into the platform.
"""

from __future__ import annotations

import re
from pathlib import Path

PUBLIC_SLUG = "TemTech-Solutions/attack-path-elimination"
# Full commit of the action consumers run. A branch name or moving tag is not a pin.
# .github/workflows/pin-action.yml rewrites this on each push to main.
PUBLIC_REF = "e0b0be88313696dc4a2e8e8d4059b35f83ab8f6d"
CHECKOUT_REF = "11d5960a326750d5838078e36cf38b85af677262"  # actions/checkout v4.4.0
PUBLIC_URL = f"https://github.com/{PUBLIC_SLUG}"
PUBLIC_GIT = f"{PUBLIC_URL}.git"
PUBLIC_WORKFLOW = (
    "https://raw.githubusercontent.com/"
    f"{PUBLIC_SLUG}/main/install/github/attack-paths.yml"
)


class InstallError(Exception):
    pass


def install(
    target: Path,
    *,
    platform: str = "github",
    tool: str | None = None,
    ref: str = PUBLIC_REF,
    force: bool = False,
) -> Path:
    root = Path(target).resolve()
    if not root.is_dir():
        raise InstallError(f"{root} is not a directory")
    platform = platform.lower()
    if platform == "github":
        slug = _github_slug(tool) if tool else PUBLIC_SLUG
        destination = root / ".github" / "workflows" / "attack-paths.yml"
        content = _github_workflow(slug, ref)
    elif platform == "gitlab":
        url = _https_url(tool) if tool else PUBLIC_GIT
        destination = root / "attack-paths.gitlab-ci.yml"
        content = _gitlab_ci(url, ref)
    else:
        raise InstallError("platform must be github or gitlab")
    if destination.exists() and not force:
        raise InstallError(f"{destination} already exists. Pass --force to replace it.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8", newline="\n")
    return destination


def _github_workflow(slug: str, ref: str) -> str:
    action = f"{slug}@{ref}"
    source = f"https://github.com/{slug}"
    return f"""# Installed from {source}
name: Attack paths

on:
  pull_request:
  push:
    branches: [main, master]

permissions:
  contents: read
  pull-requests: write

jobs:
  attack-paths:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout this repository
        uses: actions/checkout@{CHECKOUT_REF} # v4.4.0

      - name: Analyze attack paths
        uses: {action}
"""


def _gitlab_ci(tool_url: str, ref: str) -> str:
    return f"""# Installed from {PUBLIC_URL}
# Include this file from the repository's .gitlab-ci.yml:
# include:
#   - local: attack-paths.gitlab-ci.yml
attack-paths:
  image: python:3.12
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  script:
    - git init "$CI_PROJECT_DIR/.pathfinder-tool"
    - git -C "$CI_PROJECT_DIR/.pathfinder-tool" remote add origin {tool_url}
    - git -C "$CI_PROJECT_DIR/.pathfinder-tool" fetch --depth 1 origin {ref}
    - git -C "$CI_PROJECT_DIR/.pathfinder-tool" checkout --detach FETCH_HEAD
    - python -m pip install --upgrade pip
    - python -m pip install -r "$CI_PROJECT_DIR/.pathfinder-tool/requirements.txt"
    - PYTHONPATH="$CI_PROJECT_DIR/.pathfinder-tool" python -m pathfinder analyze . --out attack-paths-report
  artifacts:
    when: always
    paths:
      - attack-paths-report/report.html
      - attack-paths-report/graph.html
      - attack-paths-report/threat-model.html
      - attack-paths-report/graph-report.md
      - attack-paths-report/pr-comment.md
      - attack-paths-report/graph.json
"""


def _github_slug(value: str) -> str:
    value = value.strip().removesuffix(".git")
    https = re.fullmatch(r"https://github\.com/([^/]+)/([^/]+)", value)
    if https:
        return f"{https.group(1)}/{https.group(2)}"
    ssh = re.fullmatch(r"git@github\.com:([^/]+)/([^/]+)", value)
    if ssh:
        return f"{ssh.group(1)}/{ssh.group(2)}"
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        return value
    raise InstallError("GitHub --tool must look like owner/repository or https://github.com/owner/repository")


def _https_url(value: str) -> str:
    slug = _github_slug(value)
    return f"https://github.com/{slug}.git"

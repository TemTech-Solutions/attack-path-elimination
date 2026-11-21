"""Plain-language description of what a repository appears to do.

The text is built from files and components the scan already read.
It does not run the program, and it does not guess a business purpose
that the files do not support.
"""

from __future__ import annotations

from pathfinder.model import RepoModel


def describe_application(model: RepoModel) -> dict:
    nodes = list(model.nodes.values())
    languages = sorted({str(node.get("language")) for node in nodes if node.get("language")})
    endpoints = []
    seen_routes = set()
    for node in nodes:
        if node.get("kind") != "endpoint":
            continue
        label = node.get("receives") or node.get("name") or ""
        if not label or label in seen_routes:
            continue
        seen_routes.add(label)
        endpoints.append(label)
    platforms = _platforms(nodes)
    summary = _summary(languages, endpoints, platforms)
    return {
        "summary": summary,
        "languages": [_title(name) for name in languages],
        "entries": endpoints[:8],
        "platforms": platforms,
    }


def _summary(languages: list[str], endpoints: list[str], platforms: list[str]) -> str:
    parts = []
    if languages and endpoints:
        route_word = "route" if len(endpoints) == 1 else "routes"
        listed = _sample(endpoints, 4)
        if len(endpoints) > 4:
            routes = f"The files expose {len(endpoints)} HTTP {route_word}, including {listed}."
        else:
            routes = f"The files expose {len(endpoints)} HTTP {route_word}: {listed}."
        parts.append(f"This repository contains a {_join(_title(name) for name in languages)} application. {routes}")
    elif languages:
        parts.append(
            f"This repository contains {_join(_title(name) for name in languages)} code. "
            "No HTTP route was found in the files."
        )
    elif endpoints:
        parts.append(f"This repository exposes {_join(endpoints[:4])}.")
    else:
        parts.append("This repository does not contain a recognized application entry.")
    if platforms:
        parts.append(f"The same tree also includes {_join(platforms)}.")
    parts.append("The scan reads these files. It does not run the program.")
    return " ".join(parts)


def _platforms(nodes: list[dict]) -> list[str]:
    kinds = {node.get("kind") for node in nodes}
    files = {str(node.get("file") or "").replace("\\", "/").lower() for node in nodes}
    found = []
    if "workflow" in kinds or any("/.github/workflows/" in f"/{name}" for name in files):
        found.append("a GitHub Actions workflow")
    if any(name.endswith(".gitlab-ci.yml") for name in files):
        found.append("a GitLab CI pipeline")
    if any(name.endswith("azure-pipelines.yml") or name.endswith("azure-pipelines.yaml") for name in files):
        found.append("an Azure Pipelines definition")
    if "container" in kinds or any(name.endswith("dockerfile") or "/dockerfile" in f"/{name}" for name in files):
        found.append("a container image")
    if "workload" in kinds:
        found.append("a Kubernetes workload")
    if any(name.endswith(".tf") for name in files):
        found.append("Terraform")
    if "bucket" in kinds or "cloud" in kinds:
        found.append("cloud resources")
    if "datastore" in kinds:
        found.append("a data store")
    return found


def _sample(items: list[str], limit: int) -> str:
    return _join(items[:limit])


def _title(name: str) -> str:
    labels = {
        "javascript": "JavaScript",
        "typescript": "TypeScript",
        "python": "Python",
        "java": "Java",
        "go": "Go",
        "csharp": "C#",
        "php": "PHP",
        "ruby": "Ruby",
        "rust": "Rust",
        "kotlin": "Kotlin",
        "c": "C",
    }
    return labels.get(name.lower(), name[:1].upper() + name[1:] if name else name)


def _join(items) -> str:
    values = [str(item) for item in items if item]
    if not values:
        return ""
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} and {values[1]}"
    return ", ".join(values[:-1]) + f", and {values[-1]}"

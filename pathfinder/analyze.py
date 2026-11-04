"""Walk a repository and return a scored attack graph."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from pathfinder.baseline import FAMILIES, rule_family
from pathfinder.chains import build_paths
from pathfinder.graphview import attach_graph
from pathfinder.languages import (
    analyze_csharp,
    analyze_go,
    analyze_java,
    analyze_javascript,
    analyze_php,
    _materialize_polyglot_sql,
    parse_python,
    resolve_python,
)
from pathfinder.model import RepoModel
from pathfinder.platform import (
    analyze_azure_pipeline,
    analyze_docker,
    analyze_github_workflow,
    analyze_gitlab,
    analyze_kubernetes,
    analyze_ai,
    analyze_cloudformation,
    analyze_embedded_secret,
    analyze_openapi,
    analyze_package_json,
    analyze_requirements,
    analyze_sql,
    analyze_terraform,
    connect_runtime,
    looks_like_cloudformation,
)
from pathfinder.adapt import adapt_repository
from pathfinder.scoring import score_path
from pathfinder.universal import analyze_unclaimed, deepen

SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
    "out", "data", ".pathfinder", ".pytest_cache",
}
CODE = {
    ".js": analyze_javascript,
    ".jsx": analyze_javascript,
    ".mjs": analyze_javascript,
    ".ts": analyze_javascript,
    ".tsx": analyze_javascript,
    ".java": analyze_java,
    ".go": analyze_go,
    ".cs": analyze_csharp,
    ".php": analyze_php,
}


def analyze(target: Path) -> dict:
    root = Path(target).resolve()
    if not root.exists():
        raise FileNotFoundError(root)
    if root.is_file():
        root = root.parent
    model = RepoModel(root)
    python_facts = []
    openapi_files = []
    for path in _files(root):
        rel = model.rel(path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            model.error(rel, str(exc))
            continue
        suffix = path.suffix.lower()
        name = path.name.lower()
        claimed = False
        try:
            if suffix == ".py":
                python_facts.extend(parse_python(rel, text))
                claimed = True
            elif suffix in CODE:
                CODE[suffix](model, rel, text)
                claimed = True
            elif name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
                analyze_docker(model, rel, text)
                claimed = True
            elif suffix == ".tf":
                analyze_terraform(model, rel, text)
                claimed = True
            elif suffix == ".sql":
                analyze_sql(model, rel, text)
                claimed = True
            elif name == "requirements.txt":
                analyze_requirements(model, rel, text)
                claimed = True
            elif name == "package.json":
                analyze_package_json(model, rel, text)
                claimed = True
            elif "/.github/workflows/" in f"/{rel}" and suffix in {".yml", ".yaml"}:
                analyze_github_workflow(model, rel, text)
                claimed = True
            elif name == ".gitlab-ci.yml":
                analyze_gitlab(model, rel, text)
                claimed = True
            elif name in {"azure-pipelines.yml", "azure-pipelines.yaml"}:
                analyze_azure_pipeline(model, rel, text)
                claimed = True
            elif suffix in {".yml", ".yaml", ".json"} and looks_like_cloudformation(text):
                analyze_cloudformation(model, rel, text)
                claimed = True
            elif suffix in {".yml", ".yaml"} and _looks_openapi(text):
                openapi_files.append((rel, text))
                claimed = True
            elif suffix in {".yml", ".yaml"} and _looks_k8s(text):
                analyze_kubernetes(model, rel, text)
                claimed = True
            if not claimed:
                analyze_unclaimed(model, rel, text)
            if suffix in {".py", ".js", ".jsx", ".mjs", ".ts", ".tsx", ".ipynb"}:
                analyze_ai(model, rel, text)
            analyze_embedded_secret(model, rel, text)
        except SyntaxError as exc:
            model.error(rel, f"syntax: {exc}")
        except Exception as exc:  # one bad file should not drop the rest of the graph
            model.error(rel, f"{type(exc).__name__}: {exc}")
    try:
        resolve_python(model, python_facts)
    except SyntaxError as exc:
        model.error("<python>", str(exc))
    for rel, text in openapi_files:
        analyze_openapi(model, rel, text)
    connect_runtime(model)
    _materialize_polyglot_sql(model)
    deepen(model, root)
    adapt_repository(model)
    paths = build_paths(model)
    packaged = _package(model, paths)
    from pathfinder.query import attach_search

    return attach_search(packaged)


def _package(model: RepoModel, paths: list[dict]) -> dict:
    incoming = Counter(edge["target"] for edge in model.edges)
    outgoing = Counter(edge["source"] for edge in model.edges)
    touched = Counter(node_id for path in paths for node_id in path["node_ids"])
    findings = []
    for observation in model.observations:
        scored = score_path(
            {observation.get("exposure") or "internal"},
            {observation.get("privilege") or "none"},
            {observation.get("asset") or "internal"},
            {observation.get("exploitability") or "misconfiguration"},
        )
        findings.append({**observation, "score": scored["score"], "band": scored["band"]})
    findings.sort(key=lambda item: -item["score"])
    nodes = []
    for node in model.nodes.values():
        node = dict(node)
        node["incoming"] = incoming[node["id"]]
        node["outgoing"] = outgoing[node["id"]]
        node["attack_paths"] = touched[node["id"]]
        node["risk"] = max((path["score"] for path in paths if node["id"] in path["node_ids"]), default=0)
        nodes.append(node)
    components = [
        {
            "component": node["component"],
            "kind": node["kind"],
            "file": node["file"],
            "line": node["line"],
            "calls": node["calls"],
            "receives": node["receives"],
            "risk": node["risk"],
        }
        for node in nodes
        if node["kind"] in {"function", "endpoint", "workload", "bucket", "workflow", "secret"}
    ]
    critical = [path for path in paths if path["band"] == "Critical"]
    identity = [path for path in paths if path["flags"]["identity"]]
    cloud = [path for path in paths if path["flags"]["cloud"]]
    supply = [path for path in paths if path["flags"]["supply_chain"]]
    ai_paths = [path for path in paths if path["flags"].get("ai")]
    families = {name: 0 for name in FAMILIES}
    for item in findings:
        family = item.get("family") or rule_family(str(item.get("rule") or ""))
        families[family] = families.get(family, 0) + 1

    def worst(group):
        return max((path["score"] for path in group), default=0)

    scorecard = {
        "repository": model.root.name,
        "applications": 1,
        "components": sum(1 for node in nodes if node["kind"] == "function"),
        "endpoints": sum(1 for node in nodes if node["kind"] == "endpoint"),
        "critical_paths": len(critical),
        "high_paths": sum(1 for path in paths if path["band"] == "High"),
        "identity_paths": len(identity),
        "cloud_paths": len(cloud),
        "supply_chain_paths": len(supply),
        "business_logic_paths": sum(1 for path in paths if path["flags"]["business_logic"]),
        "attack_path_score": worst(paths),
        "privilege_risk": worst(identity),
        "identity_risk": worst(identity),
        "cloud_risk": worst(cloud),
        "supply_chain_risk": worst(supply),
        "ai_paths": len(ai_paths),
        "ai_risk": worst(ai_paths),
        "control_families": families,
        "hierarchy": "deletion > constraint",
        "findings": len(findings),
    }
    per = {
        "eligible": len(paths),
        "erased": 0,
        "rate": 0.0,
        "formula": "P_erased / P_eligible",
        "note": "This run is the baseline. A later run counts a path as erased when its chain is gone.",
    }
    packaged = {
        "repository": model.root.name,
        "root": str(model.root),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "nodes": nodes,
        "edges": model.edges,
        "observations": model.observations,
        "findings": findings,
        "components": components,
        "paths": paths,
        "scorecard": scorecard,
        "per": per,
        "parse_errors": model.parse_errors,
        "trend": None,
        "adaptation": getattr(model, "adaptation", None),
    }
    return attach_graph(packaged)


def apply_history(result: dict, state_path: Path | None) -> dict:
    if state_path is None:
        return result
    state_path.parent.mkdir(parents=True, exist_ok=True)
    history = []
    if state_path.exists():
        import json
        history = json.loads(state_path.read_text(encoding="utf-8"))
    previous = history[-1] if history else None
    current_ids = [path["id"] for path in result["paths"]]
    if previous:
        erased = len(set(previous.get("path_ids", [])) - set(current_ids))
        eligible = previous.get("eligible") or len(previous.get("path_ids", [])) or 0
        result["per"] = {
            "eligible": eligible,
            "erased": erased,
            "rate": 0 if not eligible else round(erased / eligible, 4),
            "formula": "P_erased / P_eligible",
            "note": "Erased paths were present in the previous run and are absent now.",
        }
        previous_critical = previous.get("critical", 0)
        current_critical = result["scorecard"]["critical_paths"]
        result["trend"] = {
            "previous_critical": previous_critical,
            "current_critical": current_critical,
            "reduction": None if not previous_critical else round((previous_critical - current_critical) / previous_critical, 4),
        }
    snapshot = {
        "at": result["generated_at"],
        "path_ids": current_ids,
        "critical": result["scorecard"]["critical_paths"],
        "eligible": len(current_ids),
    }
    history.append(snapshot)
    import json
    state_path.write_text(json.dumps(history, indent=2), encoding="utf-8")
    return result


def _files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.stat().st_size > 1_000_000:
            continue
        yield path


def _looks_k8s(text: str) -> bool:
    return "apiVersion:" in text and "kind:" in text


def _looks_openapi(text: str) -> bool:
    return "openapi:" in text[:400] or "swagger:" in text[:400]

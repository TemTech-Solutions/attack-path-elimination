"""Threat model for one analyzed repository.

The model is the attack graph read through the frameworks the scan already
applies. Each entry is a walk that is present in the files, the framework
that classifies it, and the edge to delete or constrain.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from pathfinder.agents import _frameworks
from pathfinder.query import FRAMEWORKS, roles_for

ASSET_KINDS = {"secret", "datastore", "bucket", "cloud", "endpoint", "trigger", "workload", "container"}

BOUNDARIES = (
    ("Untrusted entry", {"endpoint", "trigger", "exposure"}),
    ("Application", {"function"}),
    ("Data", {"datastore", "bucket"}),
    ("Identity and cloud", {"secret", "cloud"}),
    ("Build and deploy", {"workflow", "container", "workload", "dependency"}),
)


def build_threat_model(result: dict) -> dict:
    observations = result.get("observations") or []
    obs_by: dict[str, list[dict]] = defaultdict(list)
    for item in observations:
        if item.get("node_id"):
            obs_by[item["node_id"]].append(item)
    assets = []
    boundary_counts = {name: 0 for name, _kinds in BOUNDARIES}
    for node in result.get("nodes") or []:
        kind = node.get("kind") or ""
        for name, kinds in BOUNDARIES:
            if kind in kinds:
                boundary_counts[name] += 1
        if kind not in ASSET_KINDS:
            continue
        roles = sorted(roles_for(node, obs_by.get(node["id"]) or []))
        assets.append(
            {
                "name": node.get("name") or "",
                "kind": kind,
                "file": node.get("file"),
                "line": node.get("line"),
                "roles": roles[:8],
            }
        )
    threats = _threats(result)
    catalog = []
    for framework in result.get("frameworks") or _catalog_from_names(threats):
        name = framework.get("name") or framework
        count = sum(1 for threat in threats if name in threat["frameworks"])
        catalog.append(
            {
                "name": name,
                "focus": framework.get("focus") if isinstance(framework, dict) else "",
                "reviewed": True,
                "matched": count > 0 or bool(framework.get("matched")) if isinstance(framework, dict) else count > 0,
                "count": count,
            }
        )
    if not catalog:
        catalog = _catalog_from_names(threats)
    critical = sum(1 for threat in threats if threat["band"] == "Critical")
    return {
        "repository": result.get("repository") or "repository",
        "summary": {
            "threats": len(threats),
            "critical": critical,
            "frameworks": sum(1 for item in catalog if item["matched"]),
            "assets": len(assets),
        },
        "frameworks": catalog,
        "boundaries": [{"name": name, "count": boundary_counts[name]} for name, _kinds in BOUNDARIES],
        "assets": assets,
        "threats": threats,
        "adaptation": result.get("adaptation") or {},
        "notes": [
            {
                "agent": note.get("agent") or "",
                "framework": note.get("framework") or "",
                "detail": note.get("detail") or "",
            }
            for note in result.get("agent_reviews") or []
            if note.get("detail")
        ],
    }


def render_threat_html(result: dict) -> str:
    template = (Path(__file__).parent / "templates" / "threat.html").read_text(encoding="utf-8")
    payload = json.dumps(build_threat_model(result), ensure_ascii=False).replace("<", "\\u003c")
    return template.replace("__PAYLOAD__", payload)


def _threats(result: dict) -> list[dict]:
    threats = []
    seen = set()
    for path in result.get("paths") or []:
        item = _from_path(path, path.get("category") or "composed", result)
        key = (item["narrative"], tuple(item["node_ids"]))
        if key in seen:
            continue
        seen.add(key)
        threats.append(item)
    for hypothesis in result.get("hypotheses") or []:
        if not hypothesis.get("found"):
            continue
        name = hypothesis.get("name") or "Objective"
        for path in hypothesis.get("paths") or []:
            item = _from_path(path, name, result, question=hypothesis.get("question") or "")
            key = (item["narrative"], tuple(item["node_ids"]))
            if key in seen:
                continue
            seen.add(key)
            threats.append(item)
    covered = set()
    for threat in threats:
        for hop in threat["hops"]:
            covered.add((hop.get("rule") or "", hop.get("file"), hop.get("line")))
    for finding in result.get("findings") or []:
        key = (finding.get("rule") or "", finding.get("file"), finding.get("line"))
        if key in covered:
            continue
        covered.add(key)
        threats.append(_from_finding(finding, result))
    threats.sort(key=lambda item: (-item["score"], item["name"]))
    return threats


def _from_finding(finding: dict, result: dict) -> dict:
    synthetic = {
        "category": finding.get("theme") or "review",
        "band": finding.get("band") or "",
        "score": finding.get("score") or 0,
        "narrative": f"{finding.get('title') or 'Finding'}. {finding.get('evidence') or ''}".strip(),
        "node_ids": [finding["node_id"]] if finding.get("node_id") else [],
        "hops": [
            {
                "label": finding.get("title") or "",
                "file": finding.get("file"),
                "line": finding.get("line"),
                "evidence": finding.get("evidence") or "",
                "rule": finding.get("rule") or "",
                "roles": [],
            }
        ],
        "recommendations": [finding["recommendation"]] if finding.get("recommendation") else [],
        "exposure": finding.get("exposure"),
        "privilege": finding.get("privilege"),
        "asset": finding.get("asset"),
        "exploitability": finding.get("exploitability"),
        "missing_controls": [],
    }
    return _from_path(synthetic, finding.get("title") or "Finding", result)


def _from_path(path: dict, name: str, result: dict, question: str = "") -> dict:
    frameworks = list(path.get("frameworks") or [])
    for tag in _frameworks(path, result):
        if tag not in frameworks:
            frameworks.append(tag)
    hops = []
    for hop in path.get("hops") or []:
        hops.append(
            {
                "label": hop.get("label") or "",
                "file": hop.get("file"),
                "line": hop.get("line"),
                "evidence": hop.get("evidence") or "",
                "rule": hop.get("rule") or "",
            }
        )
    remove = list(path.get("recommendations") or path.get("remove") or [])
    notes = []
    for note in path.get("notes") or []:
        text = note.get("detail") or ""
        if text and text not in notes:
            notes.append(text)
        extra = note.get("remove")
        if extra and extra not in remove:
            remove.append(extra)
    labels = path.get("labels") or [hop["label"] for hop in hops if hop["label"]]
    narrative = path.get("narrative") or ("An attacker can move from " + " → ".join(labels) + "." if labels else name)
    return {
        "name": name,
        "band": path.get("band") or "",
        "score": path.get("score") or 0,
        "narrative": narrative,
        "question": question,
        "frameworks": frameworks,
        "stride": _stride(path, result),
        "dread": {
            "exposure": path.get("exposure"),
            "privilege": path.get("privilege"),
            "asset": path.get("asset"),
            "exploitability": path.get("exploitability"),
        },
        "missing_controls": list(path.get("missing_controls") or []),
        "hops": hops,
        "remove": remove,
        "notes": notes,
        "node_ids": list(path.get("node_ids") or []),
    }


def _stride(path: dict, result: dict) -> list[str]:
    wanted = set(path.get("node_ids") or [])
    themes = {item.get("theme") for item in result.get("observations") or [] if item.get("node_id") in wanted}
    roles = set()
    for hop in path.get("hops") or []:
        roles.update(hop.get("roles") or [])
    found = []
    if themes & {"unauthenticated", "authz"} or "AUTHORIZATION_CHECK" in (path.get("missing_controls") or []):
        found.append("Spoofing")
    if themes & {"sqli", "rce", "schema", "logic"}:
        found.append("Tampering")
    if themes & {"sqli", "credential", "ssrf"} or roles & {"SECRET", "PII_DATABASE", "PCI_DATA", "FINANCIAL_DATA"}:
        found.append("Information disclosure")
    if themes & {"iam", "authz"} or roles & {"IAM_ADMIN", "ADMIN_FUNCTION", "ADMIN_POLICY"}:
        found.append("Elevation of privilege")
    if themes & {"agency"}:
        found.append("Denial of service")
    return found


def _catalog_from_names(threats: list[dict]) -> list[dict]:
    counts: dict[str, int] = {}
    focus = {item["name"]: item["focus"] for item in FRAMEWORKS}
    for threat in threats:
        for name in threat["frameworks"]:
            counts[name] = counts.get(name, 0) + 1
    return [
        {"name": name, "focus": focus.get(name, ""), "reviewed": True, "matched": count > 0, "count": count}
        for name, count in sorted(counts.items())
    ]

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
        "focus_theme": finding.get("theme") or "review",
        "learned": bool(finding.get("learned")),
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
    item = {
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
        "learned": bool(path.get("learned")),
    }
    item.update(_review(item, path, result))
    return item


def _review(item: dict, path: dict, result: dict) -> dict:
    themes = _themes(path, result)
    if path.get("learned"):
        themes.add("learned")
    hops = item["hops"]
    files = {hop.get("file") for hop in hops if hop.get("file")}
    exposure = _factor(item["dread"].get("exposure"), EXPOSURE)
    privilege = _factor(item["dread"].get("privilege"), PRIVILEGE)
    asset = _factor(item["dread"].get("asset"), ASSET)
    exploit = _factor(item["dread"].get("exploitability"), EXPLOITABILITY)
    reachability = _reachability(hops, themes, exposure)
    level = _level(exploit)
    if path.get("focus_theme"):
        learned = bool(path.get("learned"))
    else:
        learned = bool(path.get("learned")) or any(
            obs.get("learned") for obs in result.get("observations") or [] if obs.get("node_id") in set(item["node_ids"])
        )
    gap = _gap(files, item["missing_controls"], learned, themes, hops)
    band = item["band"] or "Unscored"
    why = f"{band} {item['score']}. {reachability}. Exploitability {level}. {gap}"
    return {
        "severity": band,
        "reachability": reachability,
        "exploitability_level": level,
        "dread_groups": _dread_groups(exposure, asset, exploit, themes, reachability),
        "pasta": _pasta(themes, hops, learned, bool(path.get("focus_theme"))),
        "why": why,
        "effect": _effect(themes, item["dread"]),
        "recommendation": item["remove"][0] if item["remove"] else "",
        "learned": learned,
    }


def _themes(path: dict, result: dict) -> set[str]:
    if path.get("focus_theme"):
        return {path["focus_theme"]}
    wanted = set(path.get("node_ids") or [])
    themes = {item.get("theme") for item in result.get("observations") or [] if item.get("node_id") in wanted and item.get("theme")}
    category = str(path.get("category") or "")
    if category in {"injection"}:
        themes.add("sqli")
    if category in {"remote_execution", "model_execution"}:
        themes.add("rce")
    if category in {"cloud_escalation"}:
        themes.update({"ssrf", "credential"})
    if category in {"privilege_expansion"}:
        themes.add("iam")
    return themes


def _factor(value, table: dict[str, float]) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and value in table:
        return table[value]
    return None


def _level(exploit: float | None) -> str:
    if exploit is None:
        return "Not scored"
    if exploit >= 0.85:
        return "High"
    if exploit >= 0.7:
        return "Moderate"
    return "Lower"


def _reachability(hops: list[dict], themes: set[str], exposure: float | None) -> str:
    if len(hops) >= 2 and (themes & {"unauthenticated", "trigger", "public_bucket"} or (exposure is not None and exposure >= 0.9)):
        return "Reachable from an entry"
    if len(hops) >= 2:
        return "Connected walk"
    return "Local signal"


def _dread_groups(exposure, asset, exploit, themes: set[str], reachability: str) -> list[str]:
    groups = []
    if asset is not None and asset >= 0.85:
        groups.append("Damage")
    if reachability != "Local signal":
        groups.append("Reproducibility")
    if exploit is not None and exploit >= 0.85:
        groups.append("Exploitability")
    if exposure is not None and exposure >= 0.9:
        groups.append("Affected users")
    if themes & {"unauthenticated", "trigger", "public_bucket"} or (exposure is not None and exposure >= 0.9):
        groups.append("Discoverability")
    return groups or ["Not scored"]


def _pasta(themes: set[str], hops: list[dict], learned: bool, local: bool) -> str:
    if len(hops) >= 2 and not local:
        return "Stage 6 · Attack modeling"
    if local and (learned or "review" in themes or "learned" in themes):
        return "Stage 4 · Threat analysis"
    if themes & {"unauthenticated", "authz", "sqli", "rce", "ssrf", "credential", "iam"}:
        return "Stage 5 · Weakness analysis"
    if learned or "review" in themes:
        return "Stage 4 · Threat analysis"
    return "Stage 7 · Risk and impact"


def _gap(files: set[str], missing: list, learned: bool, themes: set[str], hops: list[dict]) -> str:
    if len(files) >= 2:
        return "A single-file scanner does not keep this walk together."
    if missing:
        return "This is a missing control, which a signature scanner does not report."
    if len(hops) >= 2:
        return "The priority is the connected walk, not one isolated rule."
    if learned or "review" in themes:
        return "This comes from the structure of this repository, not from a public vulnerability signature."
    return "The signal is local to this component. Confirm the file and line."


def _effect(themes: set[str], dread: dict) -> str:
    asset = str(dread.get("asset") or "")
    privilege = str(dread.get("privilege") or "")
    if "credential" in themes or asset == "credential" or privilege == "credential":
        return "Effect: credential material is the asset at risk on this walk."
    if "rce" in themes or privilege == "rce":
        return "Effect: the process is the asset at risk because a dynamic execution primitive is on this walk."
    if themes & {"sqli", "database"} or asset in {"sensitive", "financial"}:
        return "Effect: stored data is the asset at risk because this walk reaches it."
    if "iam" in themes or privilege == "admin":
        return "Effect: administrative authority is the asset at risk."
    if themes & {"ssrf", "metadata"} or privilege == "ssrf":
        return "Effect: the service's outbound reach is the asset at risk."
    if themes & {"unauthenticated", "authz"}:
        return "Effect: a privileged action sits on an entry that does not show an authorization check."
    if "review" in themes or "learned" in themes:
        return "Effect: the impact stays on this component until a walk connects it to an entry."
    return "Effect: the connected components are the asset at risk."


EXPOSURE = {"public": 1.0, "untrusted_trigger": 1.0, "authenticated": 0.72, "internal": 0.5}
PRIVILEGE = {"credential": 1.0, "deploy": 1.0, "rce": 1.0, "admin": 0.95, "exposed_data": 0.9, "data": 0.85, "ssrf": 0.8, "logic": 0.78, "none": 0.35}
ASSET = {"sensitive": 1.0, "credential": 1.0, "production": 1.0, "financial": 0.86, "internal": 0.6}
EXPLOITABILITY = {"user_controlled": 0.9, "missing_auth": 0.86, "misconfiguration": 0.82, "heuristic_logic": 0.7}


def _stride(path: dict, result: dict) -> list[str]:
    if path.get("focus_theme"):
        themes = {path["focus_theme"]}
        found = []
        if themes & {"unauthenticated", "authz"}:
            found.append("Spoofing")
        if themes & {"sqli", "rce", "schema", "logic"}:
            found.append("Tampering")
        if themes & {"sqli", "credential", "ssrf"}:
            found.append("Information disclosure")
        if themes & {"iam", "authz"}:
            found.append("Elevation of privilege")
        if themes & {"agency"}:
            found.append("Denial of service")
        return found
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

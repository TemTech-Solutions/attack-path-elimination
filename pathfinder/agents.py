"""Specialist reviews over one analyzed graph.

Each reviewer looks for a class of miss that a single weak-check scanner
splits apart: a public entry that reaches an objective, a control that is
absent, or a boundary that is inconsistent inside one file. Notes name the
file and the edge to delete. They do not describe how to abuse it.
"""

from __future__ import annotations

from collections import defaultdict

from pathfinder.query import controls_for, roles_for, search


def review(result: dict, hypotheses: list[dict]) -> list[dict]:
    notes: list[dict] = []
    for hypothesis in hypotheses:
        for path in hypothesis["paths"]:
            tags = _frameworks(path, result)
            for tag in tags:
                if tag not in path["frameworks"]:
                    path["frameworks"].append(tag)
            for note in _path_notes(path, result, hypothesis["name"]):
                path["notes"].append(note)
                notes.append(note)
    slight = _slight_hypothesis(result)
    if slight["found"]:
        hypotheses.append(slight)
        notes.extend(note for path in slight["paths"] for note in path["notes"])
    return notes


def _slight_hypothesis(result: dict) -> dict:
    gaps = _gaps(result)
    paths = []
    for gap in gaps:
        hit = search(
            result,
            {
                "name": gap["name"],
                "start": ["INTERNET"],
                "target": [gap["anchor"]],
                "max_hops": 12,
                "frameworks": gap["frameworks"],
            },
        )
        for path in hit["paths"][:1]:
            path["notes"].append(
                {
                    "agent": "slight",
                    "framework": gap["frameworks"][0],
                    "detail": gap["detail"],
                    "remove": gap["remove"],
                }
            )
            if gap["remove"] not in path["remove"]:
                path["remove"].insert(0, gap["remove"])
            paths.append(path)
            break
        else:
            continue
    deduped = []
    seen = set()
    for path in paths:
        key = tuple(path["node_ids"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return {
        "name": "Slight misses",
        "summary": "Walks a single-check scanner files as separate tickets.",
        "question": "Which small boundary mistakes still connect an entry to an objective?",
        "start": ["INTERNET"],
        "target": ["OBJECTIVE"],
        "through": [],
        "conditions": [],
        "must_not_have": [],
        "declared_severity": "",
        "frameworks": ["OWASP ASVS", "STRIDE", "Attack trees"],
        "found": len(deduped),
        "paths": deduped[:8],
    }


def _gaps(result: dict) -> list[dict]:
    nodes = {node["id"]: node for node in result.get("nodes") or []}
    obs_by: dict[str, list[dict]] = defaultdict(list)
    for item in result.get("observations") or []:
        if item.get("node_id"):
            obs_by[item["node_id"]].append(item)
    gaps = []
    for node_id, node in nodes.items():
        observations = obs_by[node_id]
        roles = roles_for(node, observations)
        themes = {item.get("theme") for item in observations}
        place = _place(node)
        if "authz" in themes:
            gaps.append(_gap(node, "A role comparison grants a privileged action without an explicit allow-list.", "Delete the permissive branch. Allow the action only for an explicit role.", ["OWASP Top 10", "STRIDE", "Trike"], place))
        if "sqli" in themes:
            gaps.append(_gap(node, "Query text includes caller-controlled data.", "Delete the string-built query. Use a fixed statement.", ["OWASP Top 10", "OWASP ASVS"], place))
        if "schema" in themes:
            gaps.append(_gap(node, "The handler forwards the raw request body.", "Delete the raw-body edge. Pass a strict schema.", ["OWASP API Security Top 10", "OWASP ASVS"], place))
        if "ssrf" in themes:
            gaps.append(_gap(node, "An outbound destination is taken from the request.", "Delete request-controlled outbound fetches.", ["OWASP Top 10", "OWASP API Security Top 10"], place))
        if node.get("kind") == "secret" or "SECRET" in roles:
            gaps.append(_gap(node, "A secret sits on a component an entry may reach.", "Delete the secret from the workload, image, and pipeline.", ["OWASP Top 10", "OWASP Docker Top 10", "LINDDUN"], place))
        if "IAM_ADMIN" in roles or "ADMIN_POLICY" in roles:
            gaps.append(_gap(node, "A wildcard identity policy is in the graph.", "Delete wildcard actions and resources.", ["OWASP Top 10", "MITRE ATT&CK"], place))
        if "ADMIN_FUNCTION" in roles and "AUTHORIZATION_CHECK" not in controls_for(node, observations):
            gaps.append(_gap(node, "An admin-named function has no authorization control on this component.", "Delete the unauthenticated path into the admin function.", ["OWASP API Security Top 10", "STRIDE"], place))
        if "DEBUG_SURFACE" in roles:
            gaps.append(_gap(node, "A diagnostic route is present.", "Delete the debug, actuator, or console route.", ["OWASP Top 10", "OWASP API Security Top 10"], place))
        if "BACKUP" in roles:
            gaps.append(_gap(node, "A backup or export name is present.", "Delete broad access to snapshots, dumps, and exports.", ["Lockheed Martin Kill Chain", "OCTAVE"], place))
        if "PRIVILEGED" in roles:
            gaps.append(_gap(node, "A workload is marked privileged.", "Delete privileged execution from the deploy path.", ["OWASP Kubernetes Top 10", "OWASP Docker Top 10"], place))
        if any("signature" in (item.get("title") or "").lower() for item in observations):
            gaps.append(_gap(node, "Token signature verification is disabled.", "Delete the configuration that skips signature checks.", ["OWASP ASVS", "STRIDE"], place))
    gaps.extend(_inconsistent_auth(nodes))
    unique = []
    seen = set()
    for gap in gaps:
        if gap["anchor"] in seen:
            continue
        seen.add(gap["anchor"])
        unique.append(gap)
    return unique


def _inconsistent_auth(nodes: dict[str, dict]) -> list[dict]:
    by_file: dict[str, list[dict]] = defaultdict(list)
    for node in nodes.values():
        if node.get("kind") == "endpoint" and node.get("file"):
            by_file[node["file"]].append(node)
    gaps = []
    for file, endpoints in by_file.items():
        flags = {bool((item.get("properties") or {}).get("auth")) for item in endpoints}
        if flags != {True, False}:
            continue
        for endpoint in endpoints:
            if (endpoint.get("properties") or {}).get("auth"):
                continue
            gaps.append(
                _gap(
                    endpoint,
                    f"{file} authenticates some routes and leaves {endpoint.get('name')} open.",
                    "Delete the unauthenticated route, or require the same authentication as the sibling routes.",
                    ["OWASP ASVS", "OWASP API Security Top 10", "VAST"],
                    _place(endpoint),
                )
            )
    return gaps


def _gap(node: dict, detail: str, remove: str, frameworks: list[str], place: str) -> dict:
    name = node.get("name") or "component"
    return {
        "name": name,
        "anchor": name,
        "detail": f"{detail} {place}".strip(),
        "remove": remove,
        "frameworks": frameworks,
    }


def _path_notes(path: dict, result: dict, hypothesis: str) -> list[dict]:
    notes = []
    themes = _themes(path, result)
    roles = set()
    for hop in path["hops"]:
        roles.update(hop.get("roles") or [])
    if "AUTHORIZATION_CHECK" in (path.get("missing_controls") or []):
        notes.append(_note("access", "OWASP Top 10", "The walk starts at a public entry and never records an authorization check."))
    if "sqli" in themes:
        notes.append(_note("injection", "OWASP Top 10", "A query on this walk is built from caller-controlled data."))
    if "ssrf" in themes:
        notes.append(_note("egress", "OWASP Top 10", "An outbound fetch on this walk takes its destination from the caller."))
    if roles & {"PII_DATABASE", "PCI_DATA", "FINANCIAL_DATA"}:
        notes.append(_note("privacy", "LINDDUN", "The objective is personal, payment, or financial data."))
    if roles & {"IAM_ADMIN", "ADMIN_POLICY"}:
        notes.append(_note("elevation", "STRIDE", "The objective is an administrative identity policy."))
    if roles & {"SECRET"}:
        notes.append(_note("credential-access", "MITRE ATT&CK", "The objective is a secret or cloud credential. Tactic only."))
    if "logic" in themes or "authz" in themes:
        notes.append(_note("business", "PASTA", f"{hypothesis}: a privileged action is reachable without a tight role and state check."))
    if roles & {"SOURCE_CODE", "PRODUCTION", "PRIVILEGED"}:
        notes.append(_note("pipeline", "OWASP CI/CD Top 10", "The walk touches the build, the deploy, or a privileged workload."))
    if "ai_tool" in themes or "model_load" in themes or "rag" in themes:
        notes.append(_note("llm", "OWASP LLM Top 10", "The walk includes a model tool, a load, or retrieval."))
    return notes[:4]


def _frameworks(path: dict, result: dict) -> list[str]:
    themes = _themes(path, result)
    roles = set()
    for hop in path["hops"]:
        roles.update(hop.get("roles") or [])
    tags = ["OWASP Subtractive Hardening", "Attack trees", "PASTA", "DREAD"]
    if themes & {"sqli", "ssrf", "rce", "unauthenticated", "authz"} or "AUTHORIZATION_CHECK" in (path.get("missing_controls") or []):
        tags.append("OWASP Top 10")
    if themes & {"unauthenticated", "schema", "authz", "ssrf"} or roles & {"ADMIN_FUNCTION", "DEBUG_SURFACE"}:
        tags.append("OWASP API Security Top 10")
    if themes & {"unauthenticated", "authz", "sqli", "credential"}:
        tags.append("OWASP ASVS")
    if roles & {"SOURCE_CODE", "PRODUCTION"} or themes & {"trigger", "deploy", "action", "dependency"}:
        tags.append("OWASP CI/CD Top 10")
    if roles & {"PRIVILEGED"} or themes & {"deploy"}:
        tags.extend(["OWASP Kubernetes Top 10", "OWASP Docker Top 10"])
    if roles & {"IAM_ADMIN", "SECRET"}:
        tags.append("OWASP Serverless Top 10")
    if themes & {"ai_tool", "model_load", "rag", "agency"}:
        tags.append("OWASP LLM Top 10")
    if roles & {"PII_DATABASE", "PCI_DATA", "FINANCIAL_DATA"}:
        tags.extend(["LINDDUN", "OCTAVE"])
    if roles & {"ADMIN_FUNCTION", "IAM_ADMIN"}:
        tags.extend(["STRIDE", "Trike", "VAST"])
    if roles & {"SECRET", "IAM_ADMIN", "BACKUP"}:
        tags.extend(["MITRE ATT&CK", "Lockheed Martin Kill Chain"])
    return _unique(tags)


def _themes(path: dict, result: dict) -> set[str]:
    wanted = set(path.get("node_ids") or [])
    return {item.get("theme") for item in result.get("observations") or [] if item.get("node_id") in wanted and item.get("theme")}


def _note(agent: str, framework: str, detail: str) -> dict:
    return {"agent": agent, "framework": framework, "detail": detail}


def _place(node: dict) -> str:
    if node.get("file"):
        line = node.get("line") or 1
        return f"({node['file']}:{line})"
    return ""


def _unique(items: list[str]) -> list[str]:
    found = []
    for item in items:
        if item not in found:
            found.append(item)
    return found

"""Threat model for one analyzed repository.

The model is the attack graph read through the frameworks the scan already
applies. Each entry is a walk that is present in the files, the framework
that classifies it, and the edge to delete or constrain.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

from pathfinder.agents import _frameworks
from pathfinder.exceptions import fingerprint, hop_is_excepted, path_is_excepted
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
    threats = [item for item in _threats(result) if not path_is_excepted(item, result.get("suppressed") or [])]
    threats = [_without_excepted_hops(item, result.get("suppressed") or []) for item in threats]
    threats = [item for item in threats if item.get("hops")]
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
        "suppressed": [
            {
                "fingerprint": item.get("fingerprint") or "",
                "rule": item.get("rule") or "",
                "file": item.get("file"),
                "line": item.get("line"),
                "title": item.get("title") or "",
                "reason": item.get("reason") or "",
                "by": item.get("by") or "remediation",
            }
            for item in result.get("suppressed") or []
        ],
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


def _without_excepted_hops(threat: dict, suppressed: list[dict]) -> dict:
    hops = [hop for hop in threat.get("hops") or [] if not hop_is_excepted(hop, suppressed)]
    if hops == list(threat.get("hops") or []):
        return threat
    kept = dict(threat)
    kept["hops"] = hops
    return kept


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
                "fingerprint": fingerprint(str(hop.get("rule") or ""), str(hop.get("file") or ""), str(hop.get("evidence") or "")) if hop.get("rule") else "",
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
    band = item["band"] or "Unscored"
    primary = next((hop for hop in hops if hop.get("evidence") or hop.get("file")), hops[0] if hops else {})
    others = [hop.get("label") for hop in hops if hop.get("label") and hop is not primary]
    explained = _explain(primary, reachability, band, item["score"], level, others)
    reviewed = {
        "severity": band,
        "reachability": reachability,
        "exploitability_level": level,
        "dread_groups": _dread_groups(exposure, asset, exploit, themes, reachability),
        "pasta": _pasta(themes, hops, learned, bool(path.get("focus_theme"))),
        "why": explained["why"],
        "effect": explained["effect"],
        "recommendation": explained["recommendation"] or (item["remove"][0] if item["remove"] else ""),
        "learned": learned,
    }
    reviewed["access"] = explained["access"]
    reviewed["dread_text"] = _dread_text(item, reviewed["reachability"])
    return reviewed


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


def _brief(text: str, limit: int = 180) -> str:
    line = " ".join(str(text or "").split())
    if len(line) <= limit:
        return line
    return line[: limit - 1].rstrip() + "…"


def _basename(file: str) -> str:
    name = str(file or "").replace("\\", "/").rsplit("/", 1)[-1]
    return name or "this file"


def _spot(hop: dict) -> str:
    name = _basename(str(hop.get("file") or ""))
    line = hop.get("line")
    if line:
        return f"{name}:{line}"
    return name


def _callee(evidence: str) -> str:
    calls = re.findall(r"([A-Za-z_][\w.]{0,80})\s*\(", evidence or "")
    if not calls:
        return ""
    for name in reversed(calls):
        leaf = name.rsplit(".", 1)[-1].lower()
        if leaf in {"eval", "exec", "system", "popen", "unserialize", "loads", "load", "execute", "query", "openstream"} or "eval" in name.lower() or "exec" in name.lower():
            return name
    return calls[-1]


def _reading(evidence: str, title: str, rule: str) -> dict[str, str]:
    """Plain reason this line is an attack path, plus the change that removes it."""
    low = evidence.lower()
    call = _callee(evidence)
    named = f"`{call}`" if call else "this call"
    if any(token in low for token in ("eval(", "scriptengine", "exec(", "system(", "popen", "shell_exec", "subprocess", "processbuilder", "runtime.getruntime", "shell=true", "unserialize", "pickle", "readobject", "objectinputstream", "yaml.load")):
        return {
            "does": f"The program builds text and then runs that text with {named}.",
            "reason": "Whoever supplies the text chooses what the program does. The file no longer limits the program to one operation the author wrote.",
            "effect": f"the running program can be made to follow the text passed to {named}",
            "change": f"stop passing built text to {named} and call one fixed operation that does not run, unpack, or launch that text",
        }
    if re.search(r"\b(select|insert|update|delete)\b", low):
        return {
            "does": "The program glues a database question together from outside text, and the database treats that question as the instruction.",
            "reason": "Whoever supplies the extra text can change which records the question asks for. A question written in the file, with the value kept beside it, does not allow that.",
            "effect": "records in the database can be read or changed because the question itself is assembled here",
            "change": "write the database question in full in the file and pass the value separately",
        }
    if any(token in low for token in ("requests.", "fetch(", "openstream", "http.get", "curl_exec", "resttemplate", "webclient", "169.254.169.254", "axios", "httpx.")):
        return {
            "does": "The program opens a connection to an address taken from the surrounding code.",
            "reason": "Whoever supplies that address chooses which system this program contacts. The file should name the allowed destination itself.",
            "effect": "this program can be pointed at a system it was not meant to reach",
            "change": "name the allowed destination in the file and stop taking the address from outside input",
        }
    if rule == "APP10" or any(token in low for token in ("permitall", "anonymous", "security: []", "norole", "isauthenticated")):
        return {
            "does": "This line lets the action run without recording who is allowed to use it.",
            "reason": "A person who can reach the action can use it without a role, an owner, or a state check in this file.",
            "effect": "the action can be used by someone the file never identifies",
            "change": "require a role, an owner, and a state check before the action runs",
        }
    if any(token in low for token in ("password", "secret", "api_key", "apikey", "token=", "aws_secret", "private_key")):
        return {
            "does": "This line writes a secret into the file.",
            "reason": "Anyone who can read the file can read the secret. A secret belongs in the place the running program fetches it from, not in the source.",
            "effect": "the secret written on this line can be read with the file",
            "change": "delete the secret from the file and have the program read it from its secret store",
        }
    label = title or rule or "finding"
    return {
        "does": f"The file contains this {label}.",
        "reason": "The line is part of a path because of what it does, not because of a general category name.",
        "effect": f"what this {label} does is the thing that needs to be removed",
        "change": f"change this {label} so the file no longer does it",
    }


def _explain(hop: dict, reachability: str, band: str, score, level: str, others: list[str]) -> dict[str, str]:
    """Say why this line is an attack path, in words a non-specialist can follow."""
    evidence = _brief(str(hop.get("evidence") or ""))
    title = hop.get("label") or hop.get("title") or "this finding"
    place = _spot(hop)
    reading = _reading(evidence, str(title), str(hop.get("rule") or ""))
    quoted = f" The line is `{evidence}`." if evidence else ""
    if others:
        tail = f" The same path continues into {others[0]}."
    elif reachability == "Reachable from an entry":
        tail = " People outside the program can already reach the line, so no second file is required."
    else:
        tail = " This line is the path. No second file is required."
    where = f" at {place}" if place and place != "this file" else ""
    access = (
        f"An attacker can use {title}{where}. {reading['does']}{quoted} {reading['reason']}{tail}"
    )
    why = f"{reading['reason']} That is why it ranks {band} {score}."
    effect = f"Effect: {reading['effect']}. The line is in {place}."
    recommendation = f"In {place}, {reading['change']}."
    if evidence:
        recommendation += f" The line to change is `{evidence}`."
    return {"access": access, "why": why, "effect": effect, "recommendation": recommendation}


def _dread_text(item: dict, reachability: str) -> str:
    dread = item.get("dread") or {}
    repro = "local" if reachability == "Local signal" else "walk is in the files"
    discover = "entry is exposed" if reachability == "Reachable from an entry" else "not an exposed entry"
    damage = dread.get("asset") or "not scored"
    exploit = dread.get("exploitability") or "not scored"
    users = dread.get("exposure") or "not scored"
    return (
        f"DREAD · damage {damage} · reproducibility {repro} · exploitability {exploit} "
        f"· affected users {users} · discoverability {discover}"
    )


def attach_reviews(result: dict) -> dict:
    """Copy the threat-model review onto every finding so each page can open the same record."""
    threats = build_threat_model(result).get("threats") or []
    by_place: dict[tuple, dict] = {}
    for threat in threats:
        for hop in threat.get("hops") or []:
            by_place.setdefault((hop.get("rule") or "", hop.get("file"), hop.get("line")), threat)

    def paint(item: dict) -> None:
        if not isinstance(item, dict):
            return
        threat = by_place.get((item.get("rule") or "", item.get("file"), item.get("line")))
        if threat is None and (item.get("title") or item.get("label") or item.get("rule")):
            named = dict(item)
            named.setdefault("title", item.get("label") or item.get("title") or item.get("rule"))
            threat = _from_finding(named, result)
        if not threat:
            return
        evidence = item.get("evidence") or ""
        if not evidence:
            for candidate in threat.get("hops") or []:
                if candidate.get("file") == item.get("file") and candidate.get("line") == item.get("line") and candidate.get("evidence"):
                    evidence = candidate.get("evidence") or ""
                    break
        hop = {
            "label": item.get("title") or item.get("label") or threat.get("name") or "This finding",
            "file": item.get("file") or "",
            "line": item.get("line"),
            "evidence": evidence,
            "rule": item.get("rule") or "",
        }
        others = []
        for candidate in threat.get("hops") or []:
            label = candidate.get("label") or ""
            if label and label != hop["label"] and label not in others:
                others.append(label)
        explained = _explain(
            hop,
            threat.get("reachability") or "",
            item.get("band") or threat.get("band") or "Unscored",
            item.get("score") if item.get("score") not in (None, "") else threat.get("score") or 0,
            threat.get("exploitability_level") or "Not scored",
            others,
        )
        item["access"] = explained["access"]
        item["why"] = explained["why"]
        item["effect"] = explained["effect"]
        item["recommendation"] = explained["recommendation"]
        item["stride"] = list(threat.get("stride") or [])
        item["pasta"] = threat.get("pasta") or ""
        item["dread_text"] = threat.get("dread_text") or ""
        item["walk"] = [
            " · ".join(
                part
                for part in (hop.get("label"), hop.get("rule"), _hop_place(hop), hop.get("evidence"))
                if part
            )
            for hop in threat.get("hops") or []
        ]
        if not item.get("recommendation"):
            item["recommendation"] = threat.get("recommendation") or ""
        if not item.get("fingerprint") and item.get("rule"):
            item["fingerprint"] = fingerprint(str(item.get("rule") or ""), str(item.get("file") or ""), str(item.get("evidence") or ""))

    for finding in result.get("findings") or []:
        paint(finding)
    for observation in result.get("observations") or []:
        paint(observation)
    for path in result.get("paths") or []:
        for hop in path.get("hops") or []:
            paint(hop)
        for finding in path.get("findings") or []:
            paint(finding)
    for node in (result.get("graph") or {}).get("nodes") or []:
        for finding in node.get("findings") or []:
            paint(finding)
    return result


def _hop_place(hop: dict) -> str:
    if not hop.get("file"):
        return ""
    return str(hop["file"]) + (f":{hop['line']}" if hop.get("line") else "")


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

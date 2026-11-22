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
        "application": result.get("application") or {},
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
        "narrative": (
            finding.get("access")
            or f"{finding.get('title') or 'Finding'}. {finding.get('evidence') or ''}".strip()
        ),
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
    reviewed["foothold"] = explained["foothold"]
    reviewed["connected"] = explained["connected"]
    reviewed["dread_text"] = _dread_text(item, reviewed["reachability"])
    for key in ("database", "cwe", "cwe_name", "cwe_rank", "owasp"):
        if explained.get(key):
            reviewed[key] = explained[key]
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
    name = str(hop.get("file") or "").replace("\\", "/")
    line = hop.get("line")
    if name and line:
        return f"{name}:{line}"
    return name or "this file"


def _quotes(evidence: str) -> list[str]:
    found = []
    for match in re.finditer(r'"([^"]*)"|\'([^\']*)\'', evidence or ""):
        found.append(match.group(1) if match.group(1) is not None else match.group(2))
    return found


def _calls(evidence: str) -> list[str]:
    return re.findall(r"([A-Za-z_][\w.]{0,80})\s*\(", evidence or "")


def _callee(evidence: str) -> str:
    calls = _calls(evidence)
    for name in reversed(calls):
        leaf = name.rsplit(".", 1)[-1].lower()
        if leaf in {"eval", "exec", "system", "popen", "unserialize", "loads", "load", "execute", "query", "openstream", "url", "command"} or "eval" in name.lower() or "exec" in name.lower():
            return name
    return calls[-1] if calls else ""


def _method_and_param(evidence: str) -> tuple[str, str]:
    match = re.search(
        r"\b(?:def|function|func|void|public|private|protected|static)\s+([A-Za-z_]\w*)\s*\(\s*(?:[A-Za-z_][\w.<>\[\]]*\s+)?([A-Za-z_]\w*)",
        evidence or "",
    )
    if not match:
        return "", ""
    return match.group(1), match.group(2)


def _joined(evidence: str, call: str) -> list[tuple[str, str]]:
    """Ordered pieces inside a call that builds one argument with +."""
    if not call or "+" not in (evidence or ""):
        return []
    match = re.search(re.escape(call) + r"\s*\(([^)]*)\)", evidence)
    inner = match.group(1) if match else ""
    if "+" not in inner:
        return []
    parts: list[tuple[str, str]] = []
    for piece in inner.split("+"):
        piece = piece.strip()
        quoted = re.fullmatch(r'"([^"]*)"|\'([^\']*)\'', piece)
        if quoted:
            parts.append(("lit", quoted.group(1) if quoted.group(1) is not None else quoted.group(2)))
        elif re.fullmatch(r"[A-Za-z_][\w.]*", piece):
            parts.append(("name", piece.split(".")[-1]))
        elif piece:
            parts.append(("expr", piece))
    return parts


def _join_words(parts: list[tuple[str, str]]) -> str:
    words = []
    for kind, value in parts:
        if kind == "lit" and value == "":
            words.append("an empty string")
        elif kind == "lit":
            words.append(f'the written text "{value}"')
        elif kind == "name":
            words.append(f"the value held in {value}")
        else:
            words.append(value)
    if not words:
        return "the argument"
    if len(words) == 1:
        return words[0]
    if len(words) == 2:
        return f"{words[0]} and then {words[1]}"
    return ", then ".join(words[:-1]) + ", then " + words[-1]


def _changing_name(parts: list[tuple[str, str]], param: str) -> str:
    for kind, value in parts:
        if kind == "name":
            return value
    return param


def _fixed_text(parts: list[tuple[str, str]]) -> str:
    for kind, value in parts:
        if kind == "lit" and value:
            return value
    return ""


def _prefix_note(literal: str, variable: str, call: str) -> str:
    if not literal:
        return f"No operation is written beside {call}. {variable} is the whole argument."
    low = literal.lower()
    if "json" in low or "parse" in low:
        return (
            f'"{literal}" is a parse prefix, not a finished parse. '
            f"{call} keeps going through {variable}, which is concatenated after that prefix."
        )
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,40}", literal):
        return (
            f'"{literal}" is a short name at the front of the argument. '
            f"{call} still receives everything {variable} adds after that name."
        )
    if any(word in low for word in ("select", "insert", "update", "delete")):
        return (
            f'"{literal}" is the start of a database question. '
            f"{variable} is concatenated into that same question."
        )
    return (
        f'"{literal}" stays in the argument, and {variable} is concatenated onto it. '
        f"{call} receives both as one value."
    )


def _sql_bits(evidence: str) -> tuple[str, str, str]:
    verb = ""
    match = re.search(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", evidence or "", re.I)
    if match:
        verb = match.group(1).upper()
    table = ""
    table_match = re.search(r"\bFROM\s+([A-Za-z_][\w]*)|\bINTO\s+([A-Za-z_][\w]*)|\bUPDATE\s+([A-Za-z_][\w]*)", evidence or "", re.I)
    if table_match:
        table = next(group for group in table_match.groups() if group)
    variable = ""
    tail = (evidence or "").split("+")[-1] if "+" in (evidence or "") else ""
    skip = {"str", "int", "format", "query", "select", "from", "where", "and", "or", "execute", "executemany"}
    for name in reversed(re.findall(r"\b([A-Za-z_][\w]*)\b", tail)):
        if name.lower() not in skip:
            variable = name
            break
    return verb, table, variable


def _neighbor_labels(others: list) -> list[str]:
    labels = []
    for item in others or []:
        label = item.get("label") if isinstance(item, dict) else str(item)
        if label and label not in labels:
            labels.append(label)
    return labels


def _reading(evidence: str, title: str, rule: str, file: str = "") -> dict[str, str]:
    """Describe this line from the code on it, not from a shared paragraph."""
    low = (evidence or "").lower()
    call = _callee(evidence)
    method, param = _method_and_param(evidence)
    parts = _joined(evidence, call)
    host = f"Method {method} " if method else "This line "
    quotes = [item for item in _quotes(evidence) if item]
    learned = re.search(r"shares the token '([^']+)' with the ([a-z]+) names", evidence or "", re.I)
    if learned:
        token, kind = learned.group(1), learned.group(2)
        return {
            "does": f"This line uses the word '{token}', the same word as another {kind} finding in this repository.",
            "reason": f"It is a different line. Review it on its own.",
            "why": f"'{token}' is the word shared with the other {kind} finding.",
            "effect": f"this line stays with the other {kind} finding while it uses '{token}'",
            "change": f"if '{token}' is not the same problem, record an exception for this line. If it is, remove the {kind} use of '{token}' here",
            "anchor": f"the word '{token}'",
        }

    if parts and any(token in low for token in ("eval(", "scriptengine", "exec(", "system(", "popen", "shell_exec")):
        variable = _changing_name(parts, param)
        fixed = _fixed_text(parts)
        subject = variable or "the joined text"
        return {
            "does": f"{host}passes {call} one argument made by joining {_join_words(parts)}.",
            "reason": f"The person who supplies the text in {subject} chooses the rest of that argument. {_prefix_note(fixed, subject, call)}",
            "why": (
                f"The person who supplies the text is not held to "
                + (f'the written text "{fixed}"' if fixed else "one operation written in the file")
                + f", because {subject} is concatenated into the same argument of {call}."
            ),
            "effect": (
                f'{call} runs one argument that contains "{fixed}" and also contains {subject}'
                if fixed
                else f"{call} runs {subject} as the argument"
            ),
            "change": _execution_change(call, subject, fixed),
            "anchor": f"{call} joining {subject}" + (f' onto "{fixed}"' if fixed else ""),
        }
    if any(token in low for token in ("pickle", "unserialize", "readobject", "objectinputstream", "yaml.load")):
        carrier = param or _changing_name(parts, "") or "the loaded value"
        loader = call or "the loader on this line"
        return {
            "does": f"{host}rebuilds objects by passing {carrier} to {loader}.",
            "reason": f"{carrier} is not a data record with a fixed set of fields. {loader} accepts it as a serialized object.",
            "why": f"{loader} decides what to build from {carrier}, and this file does not list the allowed types.",
            "effect": f"{loader} can construct objects from {carrier} while loading",
            "change": f"stop passing {carrier} to {loader}, and read a data format that cannot construct objects",
            "anchor": f"{loader} rebuilding objects from {carrier}",
        }
    if any(token in low for token in ("eval(", "scriptengine", "exec(", "system(", "popen", "shell_exec", "subprocess", "processbuilder", "runtime.getruntime", "shell=true")):
        subject = param or "the argument"
        return {
            "does": f"{host}hands {subject} to {call or 'a call that runs its argument'}.",
            "reason": f"The person who supplies the text in {subject} chooses what {call or 'that call'} runs. The file does not name one fixed operation.",
            "why": f"The person who supplies the text reaches {call or 'this call'} directly through {subject}.",
            "effect": f"{call or 'the call'} runs {subject}",
            "change": f"delete the call to {call or 'this operation'} and keep {subject} as data for one operation written in full in this file",
            "anchor": f"{call or 'the call'} running {subject}",
        }
    if re.search(r"\b(select|insert|update|delete)\b", low):
        from pathfinder.plain import explain_line, not_a_query

        if not not_a_query("query", evidence or ""):
            return explain_line(evidence, "Query is built from a string", file)
    if any(token in low for token in ("requests.", "fetch(", "openstream", "http.get", "curl_exec", "resttemplate", "webclient", "169.254.169.254", "axios", "httpx.", "new url")):
        subject = param or "the address"
        destination = quotes[0] if quotes else ""
        if "169.254.169.254" in low:
            does = f"{host}contacts the instance metadata address 169.254.169.254."
            reason = "That address serves cloud credentials to the workload. This line reaches it from application code."
            why = "The metadata address is written into this request, so the workload can read the role credentials."
            effect = "the request reaches the instance metadata service"
            change = "delete the request to 169.254.169.254"
            anchor = "the request to the instance metadata address 169.254.169.254"
        elif destination:
            does = f"{host}opens {call or 'a request'} to the address \"{destination}\"."
            reason = f"The destination is the written address \"{destination}\"{(', and ' + subject + ' is also part of the address') if subject != 'the address' else ''}."
            why = f"The host this line contacts is \"{destination}\", taken from this file rather than from a fixed allowlist beside the call."
            effect = f"the request goes to \"{destination}\""
            change = f"delete the request to \"{destination}\" unless that host is the one this file is allowed to call, and stop building the address from {subject}"
            anchor = f"the request to \"{destination}\""
        else:
            does = f"{host}passes {subject} to {call or 'an outbound call'} as the address."
            reason = f"{subject} chooses the host. This file does not write the allowed host next to {call or 'the call'}."
            why = f"{call or 'The outbound call'} receives its destination from {subject}."
            effect = f"{call or 'the request'} contacts whatever host is in {subject}"
            change = f"write the allowed host in the file and stop passing {subject} to {call or 'the outbound call'}"
            anchor = f"{call or 'the outbound call'} using {subject} as the address"
        return {"does": does, "reason": reason, "why": why, "effect": effect, "change": change, "anchor": anchor}
    if rule in {"APP10", "APP01"} or any(token in low for token in ("permitall", "anonymous", "security: []", "norole", "isauthenticated")) or re.search(r"\b(GET|POST|PUT|DELETE|PATCH)\s+/", evidence or ""):
        route = evidence.strip() if re.search(r"\b(GET|POST|PUT|DELETE|PATCH)\s+/", evidence or "") else (quotes[0] if quotes else title)
        return {
            "does": f"This file publishes {route} without a role, an owner, or a required state on the same line.",
            "reason": f"A caller who can request {route} is not identified by this file before the action runs.",
            "why": f"{route} has no authorization check in this file, so the route itself is the open step.",
            "effect": f"{route} runs for a caller this file does not name",
            "change": f"erase `{route}` if the application does not need it. If the route must stay, erase the open access by requiring a role, an owner, and a state check before it runs",
            "anchor": f"the open route {route}",
        }
    if "<secret value>" in (evidence or "") or "private key" in low or low.startswith("access key"):
        assigned = ""
        assign = re.search(r"\b([A-Za-z_][\w.]*)\s*[:=]", evidence or "")
        if assign:
            assigned = assign.group(1)
        name = assigned or "the secret"
        shown = f"`{_brief(evidence, 140)}`"
        return {
            "does": f"{shown} writes a secret value into {name}.",
            "reason": f"Erase that value. Anyone who can read the file can read {name}.",
            "why": f"Reading the file is enough to read the secret in {name}.",
            "effect": f"the secret stored for {name} can be read from this file",
            "change": f"erase the secret value in {shown} and read {name} from the secret store, leaving no secret in the file",
            "anchor": f"the secret written for {name}",
        }
    if any(token in low for token in ("password", "secret", "api_key", "apikey", "token=", "aws_secret", "private_key", "aws_access")):
        assigned = ""
        assign = re.search(r"\b([A-Za-z_][\w.]*)", evidence or "")
        if assign:
            assigned = assign.group(1)
        name = assigned or "the secret"
        return {
            "does": f"This line makes {name} available to this file.",
            "reason": f"A run of this file can read {name}. The secret should stay in the secret store.",
            "why": f"{name} is reachable from this line, so the secret is part of the attack path.",
            "effect": f"{name} can be read when this file runs",
            "change": f"remove {name} from this file and keep it in the secret store",
            "anchor": f"{name} on this line",
        }
    if "*" in (evidence or "") and any(token in low for token in ("action", "resource", "principal", "0.0.0.0/0")):
        return {
            "does": f"This line grants a wildcard: `{_brief(evidence, 120)}`.",
            "reason": "The wildcard is written in the policy, so the principal is not limited to one operation and one resource.",
            "why": "A star in Action, Resource, Principal, or the network range is the whole permission.",
            "effect": "the policy allows more than the operations this workload performs",
            "change": f"erase the wildcard in `{_brief(evidence, 120)}` and name the one principal, the actions, and the resources this workload uses",
            "anchor": "the wildcard grant on this line",
        }
    from pathfinder.plain import explain_line

    return explain_line(evidence, str(title or rule or "This line"), file)


def _execution_change(call: str, variable: str, fixed: str) -> str:
    if fixed and ("json" in fixed.lower() or "parse" in fixed.lower()):
        return f'parse {variable} with a JSON parser, delete {call}, and do not concatenate "{fixed}" onto {variable}'
    if fixed:
        return (
            f'delete {call}, and stop concatenating "{fixed}" with {variable}. '
            f"Keep {variable} as data for one operation that is written in full in this file"
        )
    return f"delete {call}, and stop passing {variable} to it"


def _explain(hop: dict, reachability: str, band: str, score, level: str, others: list) -> dict[str, str]:
    """Each section states a different fact about this line."""
    raw_evidence = str(hop.get("evidence") or "")
    evidence = _brief(raw_evidence)
    title = hop.get("label") or hop.get("title") or "this finding"
    place = _spot(hop)
    reading = _reading(evidence, str(title), str(hop.get("rule") or ""), str(hop.get("file") or ""))
    where = f" at {place}" if place and place != "this file" else ""
    anchor = reading.get("anchor") or title
    labels = _neighbor_labels(others)
    if labels:
        described = []
        for item in others:
            if isinstance(item, dict) and item.get("evidence"):
                described.append(f"{item.get('label')} (`{_brief(item.get('evidence') or '', 80)}`)")
            else:
                label = item.get("label") if isinstance(item, dict) else str(item)
                if label:
                    described.append(label)
        if len(described) == 1:
            connected = (
                f"The same walk also includes {described[0]}. "
                "That step has its own line. It is not a restatement of this one."
            )
        else:
            connected = (
                "The same walk also includes "
                + ", ".join(described[:-1])
                + f", and {described[-1]}. Each of those steps has its own line."
            )
    else:
        connected = f"No other finding is tied to this line. This walk is only {place}."
    nxt = labels[0] if labels else ""
    if labels and reachability == "Reachable from an entry":
        foothold = (
            f"An outside caller can already reach {place} and continue to {nxt}. "
            f"The foothold they use here is {anchor}."
        )
    elif labels:
        foothold = f"From {anchor} in {place}, this walk continues to {nxt}."
    elif reachability == "Reachable from an entry":
        foothold = (
            f"An outside caller can reach {place} directly. "
            f"The foothold is {anchor}, and no later step is on this walk."
        )
    else:
        foothold = (
            f"This scan did not find a public page that reaches {place}. "
            f"The problem is still {anchor}. "
            f"If a page starts calling this file, that page is the way in."
        )
    access = f"An attacker can use this as an attack path to eliminate{where}. {reading['does']} {reading['reason']}"
    why = f"{reading.get('why') or reading['reason']} That is why this finding ranks {band} {score}."
    effect = f"Effect: {reading['effect']}. The line is in {place}."
    change = str(reading["change"]).strip().rstrip(".")
    if change:
        change = change[0].lower() + change[1:]
    recommendation = f"In {place}, {change}."
    if evidence and evidence not in change and evidence not in recommendation:
        recommendation += f" The line to change is `{evidence}`."
    from pathfinder.catalog import match as catalog_match

    info = catalog_match(str(hop.get("rule") or ""), raw_evidence)
    return {
        "access": access,
        "foothold": foothold,
        "connected": connected,
        "why": why,
        "effect": effect,
        "recommendation": recommendation,
        "database": info.get("database") or "",
        "cwe": info.get("cwe") or "",
        "cwe_name": info.get("cwe_name") or "",
        "cwe_rank": info.get("cwe_rank"),
        "owasp": info.get("owasp") or "",
    }


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
        seen = set()
        for candidate in threat.get("hops") or []:
            label = candidate.get("label") or ""
            if not label or label == hop["label"] or label in seen:
                continue
            seen.add(label)
            others.append(
                {
                    "label": label,
                    "evidence": candidate.get("evidence") or "",
                    "file": candidate.get("file") or "",
                }
            )
        explained = _explain(
            hop,
            threat.get("reachability") or "",
            item.get("band") or threat.get("band") or "Unscored",
            item.get("score") if item.get("score") not in (None, "") else threat.get("score") or 0,
            threat.get("exploitability_level") or "Not scored",
            others,
        )
        item["access"] = explained["access"]
        item["foothold"] = explained["foothold"]
        item["connected"] = explained["connected"]
        item["why"] = explained["why"]
        item["effect"] = explained["effect"]
        item["recommendation"] = explained["recommendation"]
        for key in ("database", "cwe", "cwe_name", "cwe_rank", "owasp"):
            if explained.get(key):
                item[key] = explained[key]
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
    from pathfinder.catalog import finding_key, path_key

    findings = result.get("findings") or []
    if isinstance(findings, list):
        findings.sort(key=finding_key)
    paths = result.get("paths") or []
    if isinstance(paths, list):
        paths.sort(key=path_key)
    from pathfinder.graphview import apply_plain_reports

    return apply_plain_reports(result)


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

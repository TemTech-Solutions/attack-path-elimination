"""Remediation exceptions.

A finding is kept when the structural evidence is still in the file. The
remediation team can mark a case as a false positive, in `.pathfinder/exceptions.yml`
or with a `pathfinder: false-positive` comment. A marked case is removed from
paths, the graph, and the threat groups on later scans. A blank reason does
not suppress anything.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import yaml

from pathfinder.model import RepoModel

EXCEPTIONS_FILE = Path(".pathfinder") / "exceptions.yml"
ACCEPTED = {"false_positive", "false-positive", "fp", "ignore"}
MARKER = re.compile(
    r"pathfinder:\s*(?:ignore|false-positive|false_positive)"
    r"(?:\s+(?P<rules>[A-Za-z][A-Za-z0-9,]{1,80}))?"
    r"(?:\s*:\s*(?P<reason>.*))?",
    re.I,
)
MIN_REASON = 8
SIGNAL_KINDS = {"secret", "datastore"}
SIGNAL_EDGES = {"USES_SECRET", "READS"}


def fingerprint(rule: str, file: str, evidence: str) -> str:
    basis = f"{(rule or '').upper()}|{(file or '').replace(chr(92), '/')}|{' '.join(str(evidence or '').split())}"
    return hashlib.sha1(basis.encode()).hexdigest()[:16]


def apply_exceptions(model: RepoModel) -> list[dict]:
    loaded, error = load_exceptions(model.root)
    if error:
        model.error(EXCEPTIONS_FILE.as_posix(), error)
        loaded = []
    kept = []
    suppressed = list(getattr(model, "suppressed", []) or [])
    texts: dict[str, dict[int, list[tuple[set[str] | None, str]]]] = {}
    for observation in model.observations:
        observation["fingerprint"] = fingerprint(
            str(observation.get("rule") or ""),
            str(observation.get("file") or ""),
            str(observation.get("evidence") or ""),
        )
        match = _match(observation, loaded, _marks_for(model.root, observation.get("file"), observation.get("line"), texts))
        if match:
            suppressed.append(
                {
                    "fingerprint": observation["fingerprint"],
                    "rule": observation.get("rule") or "",
                    "file": observation.get("file"),
                    "line": observation.get("line"),
                    "title": observation.get("title") or "",
                    "evidence": observation.get("evidence") or "",
                    "reason": match.get("reason") or "",
                    "by": match.get("by") or "remediation",
                    "node_id": observation.get("node_id"),
                }
            )
            continue
        kept.append(observation)
    model.observations = kept
    model.suppressed = suppressed
    _drop_unobserved_signals(model, {item.get("node_id") for item in suppressed})
    return suppressed


def load_exceptions(root: Path) -> tuple[list[dict], str]:
    path = Path(root) / EXCEPTIONS_FILE
    if not path.exists():
        return [], ""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        return [], f"exceptions file was not applied: {exc}"
    if not isinstance(raw, dict):
        return [], "exceptions file was not applied: the document must be a mapping"
    entries = raw.get("exceptions") or []
    if not isinstance(entries, list):
        return [], "exceptions file was not applied: exceptions must be a list"
    usable = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        status = str(entry.get("status") or "false_positive").lower().replace(" ", "_")
        reason = " ".join(str(entry.get("reason") or "").split())
        if status not in ACCEPTED or len(reason) < MIN_REASON:
            continue
        usable.append(
            {
                "fingerprint": str(entry.get("fingerprint") or ""),
                "rule": str(entry.get("rule") or "").upper(),
                "file": str(entry.get("file") or "").replace("\\", "/"),
                "line": _line(entry.get("line")),
                "evidence": " ".join(str(entry.get("evidence") or "").split()),
                "scope": str(entry.get("scope") or "finding"),
                "reason": reason,
                "by": str(entry.get("by") or "remediation"),
                "status": "false_positive",
            }
        )
    return usable, ""


def record_exception(root: Path, *, rule: str, file: str, line: int, reason: str, by: str = "remediation") -> Path:
    clean_reason = " ".join(reason.split())
    if len(clean_reason) < MIN_REASON:
        raise ValueError(f"A false-positive reason must be at least {MIN_REASON} characters")
    if line < 1:
        raise ValueError("line must be 1 or greater")
    relative = file.replace("\\", "/")
    source = Path(root) / relative
    if not source.is_file():
        raise ValueError(f"{relative} is not a file in the repository")
    lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    if line > len(lines):
        raise ValueError(f"{relative} has {len(lines)} lines")
    evidence = " ".join(lines[line - 1].split())[:180]
    entry = {
        "fingerprint": fingerprint(rule, relative, evidence),
        "rule": rule.upper(),
        "file": relative,
        "line": line,
        "evidence": evidence,
        "reason": clean_reason,
        "by": by or "remediation",
        "status": "false_positive",
    }
    path = Path(root) / EXCEPTIONS_FILE
    existing, error = load_exceptions(root)
    if error:
        raise ValueError(error)
    replaced = False
    for index, item in enumerate(existing):
        if item.get("rule") == entry["rule"] and item.get("file") == entry["file"] and item.get("line") == entry["line"]:
            existing[index] = entry
            replaced = True
            break
    if not replaced:
        existing.append(entry)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump({"version": 1, "exceptions": existing}, sort_keys=False),
        encoding="utf-8",
    )
    return path


def _match(observation: dict, entries: list[dict], marks: list[tuple[set[str] | None, str]]) -> dict | None:
    rule = str(observation.get("rule") or "").upper()
    file = str(observation.get("file") or "").replace("\\", "/")
    line = observation.get("line")
    evidence = " ".join(str(observation.get("evidence") or "").split())
    for rules, reason in marks:
        if rules and rule not in rules:
            continue
        return {"reason": reason, "by": "remediation"}
    for entry in entries:
        if entry["fingerprint"] and entry["fingerprint"] == observation.get("fingerprint"):
            return entry
        if entry["rule"] and entry["rule"] != rule:
            continue
        if entry["file"] and entry["file"] != file:
            continue
        if not entry["rule"] or not entry["file"]:
            continue
        if entry["scope"] == "file":
            return entry
        if entry["line"] and entry["line"] == line:
            return entry
        if entry["evidence"] and (entry["evidence"] in evidence or evidence in entry["evidence"]):
            return entry
    return None


def _marks_for(root: Path, file: str | None, line, texts: dict[str, dict[int, list[tuple[set[str] | None, str]]]]) -> list[tuple[set[str] | None, str]]:
    if not file:
        return []
    if file not in texts:
        path = Path(root) / file
        try:
            source = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
        except OSError:
            source = ""
        texts[file] = _inline(source)
    return texts[file].get(line or 0) or []


def _inline(text: str) -> dict[int, list[tuple[set[str] | None, str]]]:
    found: dict[int, list[tuple[set[str] | None, str]]] = {}
    lines = text.splitlines()
    for index, line in enumerate(lines, start=1):
        match = MARKER.search(line)
        if not match:
            continue
        reason = " ".join((match.group("reason") or "").split())
        if len(reason) < MIN_REASON:
            continue
        rules = {item.strip().upper() for item in (match.group("rules") or "").split(",") if item.strip()} or None
        found.setdefault(index, []).append((rules, reason))
        code = MARKER.sub("", line)
        code = re.sub(r"(#|//).*", "", code).strip()
        if not code:
            found.setdefault(index + 1, []).append((rules, reason))
    return found


def _line(value) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _drop_unobserved_signals(model: RepoModel, suppressed_nodes: set) -> None:
    live = {item.get("node_id") for item in model.observations}
    drop = set()
    for node_id in suppressed_nodes:
        node = model.nodes.get(node_id)
        if not node or node_id in live or node.get("kind") not in SIGNAL_KINDS:
            continue
        touching = [edge for edge in model.edges if edge["source"] == node_id or edge["target"] == node_id]
        if any(edge["kind"] not in SIGNAL_EDGES for edge in touching):
            continue
        drop.add(node_id)
    if not drop:
        return
    model.nodes = {node_id: node for node_id, node in model.nodes.items() if node_id not in drop}
    model.edges = [edge for edge in model.edges if edge["source"] not in drop and edge["target"] not in drop]
    model._edge_seen = {(edge["source"], edge["target"], edge["kind"]) for edge in model.edges}

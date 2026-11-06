"""Remediation exceptions.

A finding is kept when the structural evidence is still in the file. The
calling repository commits `pathfinder-exceptions.yml` at the root of the
scanned tree, or marks the line with `pathfinder: false-positive`. A marked
case is removed from paths, the graph, and the threat groups on later scans.
A blank reason does not suppress anything.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import yaml

from pathfinder.model import RepoModel

EXCEPTIONS_FILE = Path("pathfinder-exceptions.yml")
LEGACY_EXCEPTIONS_FILE = Path(".pathfinder") / "exceptions.yml"
EXCEPTION_FILES = (EXCEPTIONS_FILE, LEGACY_EXCEPTIONS_FILE)
ACCEPTED = {"false_positive", "fp", "ignore", "accepted", "skip", "skipped", "suppressed", "exception", "waived", "falsepositive"}
LINE_WINDOW = 12
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
        if not loaded:
            loaded = []
    kept = []
    suppressed = list(getattr(model, "suppressed", []) or [])
    texts: dict[str, dict[int, list[tuple[set[str] | None, str]]]] = {}
    matched: list[tuple[dict, dict]] = []
    pending = []
    for observation in model.observations:
        observation["fingerprint"] = fingerprint(
            str(observation.get("rule") or ""),
            str(observation.get("file") or ""),
            str(observation.get("evidence") or ""),
        )
        match = _match(
            model.root,
            observation,
            loaded,
            _marks_for(model.root, observation.get("file"), observation.get("line"), texts),
        )
        if match:
            matched.append((observation, match))
            continue
        pending.append(observation)
    seed = list(matched)
    for observation in pending:
        near = _near_matched(observation, seed)
        if near:
            matched.append((observation, near))
            continue
        kept.append(observation)
    for observation, match in matched:
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
    model.observations = kept
    model.suppressed = suppressed
    _drop_unobserved_signals(model, {item.get("node_id") for item in suppressed})
    return suppressed


def load_exceptions(root: Path) -> tuple[list[dict], str]:
    usable: list[dict] = []
    errors: list[str] = []
    for path in _exception_paths(Path(root)):
        relative = path.relative_to(root) if path.is_relative_to(root) else path
        batch, error = _read_exception_file(path, Path(relative))
        if error:
            errors.append(error)
            continue
        usable.extend(batch)
    return usable, "; ".join(errors)


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
    path.write_text(
        "# False positives for this repository. Commit this file at the repository root.\n"
        + yaml.safe_dump({"version": 1, "exceptions": existing}, sort_keys=False),
        encoding="utf-8",
        newline="\n",
    )
    legacy = Path(root) / LEGACY_EXCEPTIONS_FILE
    if legacy.is_file():
        legacy.unlink()
    return path


def _read_exception_file(path: Path, relative: Path) -> tuple[list[dict], str]:
    label = relative.as_posix()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        return [], f"{label} was not applied: {exc}"
    if isinstance(raw, list):
        entries = raw
    elif isinstance(raw, dict):
        entries = _field(raw, "exceptions", "exception", "items") or []
        if isinstance(entries, dict):
            entries = [entries]
    else:
        return [], f"{label} was not applied: the document must be a mapping or a list"
    if not isinstance(entries, list):
        return [], f"{label} was not applied: exceptions must be a list"
    usable = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        status = str(_field(entry, "status") or "false_positive").lower().replace(" ", "_").replace("-", "_")
        reason = " ".join(str(_field(entry, "reason", "why", "note") or "").split())
        if status not in ACCEPTED or len(reason) < MIN_REASON:
            continue
        file_value = str(_field(entry, "file", "path", "location") or "").replace("\\", "/").strip()
        line_value = _field(entry, "line", "lineno")
        if line_value in (None, "") and ":" in file_value:
            maybe_file, maybe_line = file_value.rsplit(":", 1)
            if maybe_line.isdigit():
                file_value, line_value = maybe_file, maybe_line
        usable.append(
            {
                "fingerprint": str(_field(entry, "fingerprint", "id") or ""),
                "rule": _rule(_field(entry, "rule", "rules", "control")),
                "file": file_value.lstrip("./"),
                "line": _line(line_value),
                "evidence": " ".join(str(_field(entry, "evidence") or "").split()),
                "scope": str(_field(entry, "scope") or "finding").lower(),
                "reason": reason,
                "by": str(_field(entry, "by", "author") or "remediation"),
                "status": "false_positive",
            }
        )
    return usable, ""


def _exception_paths(root: Path) -> list[Path]:
    found: list[Path] = []
    seen: set[Path] = set()
    names = {"pathfinder-exceptions.yml", "pathfinder-exceptions.yaml"}
    candidates = [root / relative for relative in EXCEPTION_FILES]
    candidates.append(root / ".github" / "pathfinder-exceptions.yml")
    if root.is_dir():
        for path in root.rglob("*"):
            if not path.is_file() or path.name.lower() not in names:
                continue
            if any(part in {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "out", "data", ".pytest_cache"} for part in path.parts):
                continue
            candidates.append(path)
    for path in candidates:
        if not path.is_file():
            continue
        try:
            key = path.resolve()
        except OSError:
            key = path
        if key in seen:
            continue
        seen.add(key)
        found.append(path)
    return found


def _match(root: Path, observation: dict, entries: list[dict], marks: list[tuple[set[str] | None, str]]) -> dict | None:
    rule = _rule(observation.get("rule"))
    file = _normalize_file(observation.get("file"))
    line = _line(observation.get("line"))
    evidence = " ".join(str(observation.get("evidence") or "").split())
    for rules, reason in marks:
        if rules and rule not in rules:
            continue
        return {"reason": reason, "by": "remediation"}
    for entry in entries:
        if entry["fingerprint"] and entry["fingerprint"] == observation.get("fingerprint"):
            return entry
        if not entry["rule"] or entry["rule"] != rule or not _files_match(entry["file"], file):
            continue
        if entry["scope"] == "file":
            return entry
        if entry["evidence"] and (entry["evidence"] in evidence or evidence in entry["evidence"]):
            return entry
        if entry["line"] and line and abs(line - entry["line"]) <= LINE_WINDOW:
            return entry
        if entry["line"] and _text_near(root, observation.get("file"), entry["line"], evidence):
            return entry
    return None


def _near_matched(observation: dict, matched: list[tuple[dict, dict]]) -> dict | None:
    rule = _rule(observation.get("rule"))
    file = _normalize_file(observation.get("file"))
    line = _line(observation.get("line"))
    if not rule or not file or not line:
        return None
    for other, match in matched:
        if _rule(other.get("rule")) != rule or _normalize_file(other.get("file")) != file:
            continue
        other_line = _line(other.get("line"))
        if other_line and abs(line - other_line) <= LINE_WINDOW:
            return match
    return None


def _files_match(entry_file: str, observation_file: str) -> bool:
    left = _normalize_file(entry_file).lower()
    right = _normalize_file(observation_file).lower()
    if not left or not right:
        return False
    return left == right or right.endswith("/" + left) or left.endswith("/" + right)


def _text_near(root: Path, file: str | None, line: int | None, evidence: str) -> bool:
    if not file or not line or len(evidence) < 8:
        return False
    path = Path(root) / str(file)
    try:
        rows = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return False
    start = max(0, line - LINE_WINDOW - 1)
    stop = min(len(rows), line + LINE_WINDOW)
    window = " ".join(" ".join(rows[start:stop]).split())
    return evidence in window or any(len(piece) >= 8 and piece in evidence for piece in (" ".join(row.split()) for row in rows[start:stop]))


def _field(entry: dict, *names: str):
    lowered = {str(key).lower(): value for key, value in entry.items()}
    for name in names:
        if name in lowered and lowered[name] not in (None, ""):
            return lowered[name]
    return None


def _rule(value) -> str:
    text = re.sub(r"[\s_-]", "", str(value or "").upper())
    numbered = re.fullmatch(r"([A-Z]+?)0*(\d+)", text)
    if numbered:
        return f"{numbered.group(1)}{int(numbered.group(2)):02d}"
    return text


def _normalize_file(value) -> str:
    return str(value or "").replace("\\", "/").strip().lstrip("./")


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


def hop_is_excepted(hop: dict, suppressed: list[dict]) -> bool:
    """A hop matches one specific exception: same fingerprint, or the same rule and file."""
    if not suppressed or not hop:
        return False
    rule = _rule(hop.get("rule"))
    file = _normalize_file(hop.get("file"))
    line = _line(hop.get("line"))
    evidence = " ".join(str(hop.get("evidence") or "").split())
    digest = str(hop.get("fingerprint") or "")
    if not digest and rule:
        digest = fingerprint(rule, file, evidence)
    for item in suppressed:
        if digest and item.get("fingerprint") and digest == item.get("fingerprint"):
            return True
        if not rule or _rule(item.get("rule")) != rule or not _files_match(str(item.get("file") or ""), file):
            continue
        other = " ".join(str(item.get("evidence") or "").split())
        if other and evidence and (other in evidence or evidence in other):
            return True
        item_line = _line(item.get("line"))
        if item_line and line and abs(line - item_line) <= LINE_WINDOW:
            return True
    return False


def path_is_excepted(path: dict, suppressed: list[dict]) -> bool:
    """Drop a walk only when every ruled hop is a specific exception."""
    ruled = [hop for hop in path.get("hops") or [] if hop.get("rule")]
    return bool(ruled) and all(hop_is_excepted(hop, suppressed) for hop in ruled)


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

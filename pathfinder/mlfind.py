"""Read one finding line with the local naive Bayes model.

The weights and the sentences live in tools/finding-ml. When Node is installed,
tools/finding-ml/classify.js performs the read. Otherwise this module runs the
same model. Either way the line stays on this machine.
"""

from __future__ import annotations

import json
import math
import re
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1] / "tools" / "finding-ml"
_NODE = shutil.which("node")
_MARKERS = (
    ("mark_sql", re.compile(r"\b(?:select|insert|update|delete)\b", re.I)),
    ("mark_secret", re.compile(r"secret|password|api_key|<secret value>", re.I)),
    ("mark_action", re.compile(r"actions/|@[vV]\d|uses:")),
    ("mark_exec", re.compile(r"\b(?:eval|system|popen|function)\b|shell=true", re.I)),
    ("mark_deser", re.compile(r"pickle|yaml\.load|unserialize|readobject|objectinputstream", re.I)),
    ("mark_ssrf", re.compile(r"requests\.|fetch\(|169\.254\.169\.254|openstream|axios|httpx", re.I)),
    ("mark_xss", re.compile(r"innerhtml|document\.write|dangerouslysetinnerhtml", re.I)),
    ("mark_auth", re.compile(r"permitall|allowany|csrf_exempt|get /|post /", re.I)),
    ("mark_wild", re.compile(r"0\.0\.0\.0/0|\*")),
    ("mark_tls", re.compile(r"verify=false|rejectunauthorized|insecureskipverify|cert_none", re.I)),
    ("mark_debug", re.compile(r"debug\s*=\s*true|display_errors", re.I)),
    ("mark_path", re.compile(r"\.\./|filepath\.join|os\.path\.join|open\(", re.I)),
    ("mark_archive", re.compile(r"extractall", re.I)),
    ("mark_jwt", re.compile(r"jwt\.decode|algorithms", re.I)),
)


@lru_cache(maxsize=1)
def _model() -> dict:
    return json.loads((_ROOT / "model.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _phrases() -> dict:
    return json.loads((_ROOT / "phrases.json").read_text(encoding="utf-8"))


def _tokens(text: str) -> set[str]:
    found = set(re.findall(r"[a-z0-9_./:@<>=-]{2,}", text.lower()))
    low = text.lower()
    for name, pattern in _MARKERS:
        if pattern.search(low):
            found.add(name)
    return found


def _classify(text: str) -> tuple[str, float]:
    present = _tokens(text)
    model = _model()
    scores = {}
    for label, weights in model["classes"].items():
        score = weights["prior"]
        for token in present:
            if token not in model["vocab"]:
                continue
            score += weights["token_log"].get(token, weights["default_log"])
        scores[label] = score
    ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    best = ranked[0][1]
    weights = [math.exp(score - best) for _, score in ranked]
    total = sum(weights) or 1.0
    return ranked[0][0], round(weights[0] / total, 3)


def _subject(label: str, evidence: str) -> str:
    if label == "sql":
        brace = re.search(r"\{([^{}]+)\}", evidence)
        if brace:
            return brace.group(1)
        plus = re.search(
            r"""["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\+\s*([^);\n]+)""",
            evidence,
            re.I,
        )
        if plus:
            return plus.group(1).strip()
    if label == "secret":
        name = re.search(r"\b([A-Za-z_][\w.]*)\s*[:=]", evidence)
        if name:
            return name.group(1)
    if label == "action":
        action = re.search(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[A-Za-z0-9._-]+", evidence)
        if action:
            return action.group(0)
    word = re.search(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\b", evidence)
    return word.group(1) if word else "the value on this line"


def _fill(template: str, values: dict[str, str]) -> str:
    return template.format(**values)


def _from_parts(label: str, confidence: float, evidence: str, file: str) -> dict:
    phrase = _phrases().get(label) or {}
    marker = phrase.get("marker") or ""
    supported = bool(marker and re.search(marker, evidence or ""))
    values = {
        "line": (evidence or "").strip()[:180],
        "subject": _subject(label, evidence or ""),
        "place": file or "this file",
    }
    return {
        "label": label,
        "confidence": confidence,
        "supported": supported,
        "description": _fill(phrase["description"], values) if supported else "",
        "effect": _fill(phrase["effect"], values) if supported else "",
        "remediation": _fill(phrase["remediation"], values) if supported else "",
    }


def _javascript(evidence: str, title: str, file: str) -> dict | None:
    if not _NODE or not (_ROOT / "model.json").is_file():
        return None
    try:
        completed = subprocess.run(
            [_NODE, str(_ROOT / "classify.js")],
            input=json.dumps({"evidence": evidence, "title": title, "file": file}),
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0 or not completed.stdout.strip():
        return None
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict) or "label" not in payload:
        return None
    return payload


@lru_cache(maxsize=512)
def describe_finding(evidence: str, title: str = "", file: str = "") -> dict:
    """Classify this line and fill a description and a remediation from it."""
    if not (_ROOT / "model.json").is_file():
        return {"label": "", "confidence": 0.0, "supported": False, "description": "", "effect": "", "remediation": ""}
    javascript = _javascript(evidence, title, file)
    if javascript is not None:
        return javascript
    label, confidence = _classify(f"{evidence} {title}")
    return _from_parts(label, confidence, evidence, file)

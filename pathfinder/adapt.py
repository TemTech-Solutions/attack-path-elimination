"""Local model of one repository.

Identifiers are hashed into a character-trigram vector. Each scan trains class
centroids from the signals this repository already confirmed, then from names
that share a long token with those signals in the same file. The centroids are
kept under `.pathfinder/` and blended into the next scan of this environment.
Nothing is sent off the machine.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

from pathfinder.baseline import rule_recommendation
from pathfinder.model import RepoModel

DIM = 48
PROFILE = ".pathfinder/environment.json"
MAX_PROMOTED = 40
FP_SEEDS = (
    "example",
    "dummy",
    "placeholder",
    "changeme",
    "fixture",
    "mock",
    "sample",
    "lorem",
    "fake",
    "stub",
    "notasecret",
)

SEEDS = {
    "credential": ("password", "secret", "api_key", "apikey", "token", "private_key", "credential", "session"),
    "privileged": ("admin", "refund", "payout", "grant_role", "impersonate", "privilege", "set_role"),
    "execution": ("eval", "exec", "system", "popen", "shell", "deserialize", "subprocess"),
    "query": ("select", "insert", "query", "execute", "rawquery"),
    "egress": ("fetch", "request", "urlopen", "metadata", "http_get"),
}
CLASS_RULE = {
    "credential": ("APP03", "credential", "Credential name matches this repository", "internal", "credential", "credential", "misconfiguration"),
    "privileged": ("APP10", "review", "Privileged name matches this repository", "internal", "admin", "internal", "missing_auth"),
    "execution": ("APP05", "review", "Execution-shaped name matches this repository", "internal", "rce", "production", "user_controlled"),
    "query": ("APP09", "review", "Query-shaped name matches this repository", "internal", "data", "sensitive", "user_controlled"),
    "egress": ("APP08", "review", "Outbound-call name matches this repository", "internal", "ssrf", "internal", "user_controlled"),
}
STOP = {"main", "init", "run", "test", "data", "value", "item", "name", "type", "self", "this", "true", "false", "null", "none", "args", "config", "error", "info"}


def adapt_repository(model: RepoModel) -> dict:
    path = model.root / PROFILE
    previous = _load(path)
    state = CentroidState.from_profile(previous)
    state.add_seeds()
    confirmed = _confirmed(model)
    for label, text in confirmed:
        state.observe(label, text, weight=1.0)
    contextual = _contextual(model, confirmed)
    for label, text in contextual:
        state.observe(label, text, weight=0.45)
    fp_vector = _false_positive_vector(model)
    promoted = _promote(model, state, contextual, fp_vector)
    held = _hold_learned_false_positives(model, state, fp_vector)
    summary = state.export(previous, promoted, _languages(model))
    _save(path, summary)
    model.adaptation = {
        "scans": summary["scans"],
        "languages": summary["languages"],
        "promoted": len(promoted),
        "held": held,
        "thresholds": summary["thresholds"],
        "method": "Local centroid classifier on identifier trigrams, retrained from this repository and blended with the previous scan of this environment.",
    }
    return model.adaptation


class CentroidState:
    def __init__(self):
        self.sum = {label: [0.0] * DIM for label in SEEDS}
        self.weight = {label: 0.0 for label in SEEDS}

    @classmethod
    def from_profile(cls, profile: dict) -> "CentroidState":
        state = cls()
        stored = profile.get("centroids") or {}
        weights = profile.get("weights") or {}
        for label in SEEDS:
            vector = stored.get(label)
            weight = float(weights.get(label) or 0) * 0.6
            if isinstance(vector, list) and len(vector) == DIM and weight > 0:
                state.sum[label] = [float(item) * weight for item in vector]
                state.weight[label] = weight
        return state

    def add_seeds(self) -> None:
        for label, words in SEEDS.items():
            for word in words:
                self.observe(label, word, weight=1.0)

    def observe(self, label: str, text: str, weight: float) -> None:
        vector = features(text)
        if not any(vector):
            return
        bucket = self.sum.setdefault(label, [0.0] * DIM)
        for index, value in enumerate(vector):
            bucket[index] += value * weight
        self.weight[label] = self.weight.get(label, 0.0) + weight

    def score(self, text: str) -> dict[str, float]:
        vector = features(text)
        return {label: _cosine(vector, self._centroid(label)) for label in SEEDS}

    def threshold(self, label: str) -> float:
        scores = [self.score(word)[label] for word in SEEDS[label]]
        scores.sort()
        median = scores[len(scores) // 2] if scores else 0.5
        return max(0.4, min(0.74, median * 0.8))

    def export(self, previous: dict, promoted: list[dict], languages: dict[str, int]) -> dict:
        counts = dict(previous.get("languages") or {})
        for name, count in languages.items():
            counts[name] = counts.get(name, 0) + count
        return {
            "version": 1,
            "scans": int(previous.get("scans") or 0) + 1,
            "languages": counts,
            "centroids": {label: self._centroid(label) for label in SEEDS},
            "weights": {label: round(self.weight[label], 3) for label in SEEDS},
            "thresholds": {label: round(self.threshold(label), 3) for label in SEEDS},
            "promoted": promoted[:MAX_PROMOTED],
        }

    def _centroid(self, label: str) -> list[float]:
        weight = self.weight.get(label) or 0
        if weight <= 0:
            return [0.0] * DIM
        raw = [value / weight for value in self.sum[label]]
        norm = sum(value * value for value in raw) ** 0.5
        if norm == 0:
            return raw
        return [value / norm for value in raw]


def features(text: str) -> list[float]:
    vector = [0.0] * DIM
    pieces = _tokens(text)
    if not pieces:
        return vector
    for piece in pieces:
        padded = f"^{piece}$"
        grams = [padded[index : index + 3] for index in range(max(len(padded) - 2, 1))]
        grams.append(piece)
        for gram in grams:
            vector[_bucket(gram)] += 1.0
    norm = sum(value * value for value in vector) ** 0.5
    if norm:
        vector = [value / norm for value in vector]
    return vector


def _false_positive_vector(model: RepoModel) -> list[float]:
    """Centroid of placeholder names plus exceptions this repository already accepted."""
    total = [0.0] * DIM
    weight = 0.0
    texts = list(FP_SEEDS)
    for item in getattr(model, "suppressed", []) or []:
        evidence = item.get("evidence") or ""
        title = item.get("title") or ""
        if evidence:
            texts.append(str(evidence)[:80])
        if title:
            texts.append(str(title)[:80])
    for text in texts:
        vector = features(text)
        if not any(vector):
            continue
        for index, value in enumerate(vector):
            total[index] += value
        weight += 1.0
    if weight <= 0:
        return [0.0] * DIM
    raw = [value / weight for value in total]
    norm = sum(value * value for value in raw) ** 0.5
    if norm == 0:
        return raw
    return [value / norm for value in raw]


def _looks_false_positive(text: str, state: CentroidState, fp_vector: list[float]) -> bool:
    """A learned name is held when it is closer to accepted false positives than to a real class."""
    if not text or not any(fp_vector):
        return False
    fp_score = _cosine(features(text), fp_vector)
    scores = state.score(text)
    best = max(scores.values()) if scores else 0.0
    return fp_score >= 0.42 and fp_score >= best


def _hold_learned_false_positives(model: RepoModel, state: CentroidState, fp_vector: list[float]) -> int:
    kept = []
    held = 0
    suppressed = list(getattr(model, "suppressed", []) or [])
    for observation in model.observations:
        if not observation.get("learned"):
            kept.append(observation)
            continue
        text = f"{observation.get('evidence') or ''} {observation.get('title') or ''}"
        if not _looks_false_positive(text, state, fp_vector):
            kept.append(observation)
            continue
        suppressed.append(
            {
                "fingerprint": "",
                "rule": observation.get("rule") or "",
                "file": observation.get("file"),
                "line": observation.get("line"),
                "title": observation.get("title") or "",
                "evidence": observation.get("evidence") or "",
                "reason": "Local learner: this name matches accepted false positives in this repository more closely than a confirmed finding.",
                "by": "local-learner",
                "node_id": observation.get("node_id"),
            }
        )
        held += 1
    model.observations = kept
    model.suppressed = suppressed
    return held


def _promote(model: RepoModel, state: CentroidState, contextual: list[tuple[str, str]], fp_vector: list[float]) -> list[dict]:
    shared: dict[tuple[str, str], set[str]] = defaultdict(set)
    for label, text in contextual:
        shared[label].update(token for token in _tokens(text) if len(token) >= 6)
    promoted = []
    seen = set()
    candidates = []
    for node in model.nodes.values():
        if node.get("kind") not in {"function", "endpoint"}:
            continue
        candidates.append(node)
    for sample in getattr(model, "samples", []) or []:
        node = model.nodes.get(sample.get("node_id"))
        if node and node not in candidates:
            candidates.append(node)
    for node in candidates:
        name = node.get("name") or ""
        key = name.lower()
        if key in STOP or key in seen or len(key) < 4:
            continue
        if any(item.get("node_id") == node["id"] and item.get("learned") for item in model.observations):
            continue
        scores = state.score(name)
        label = max(scores, key=scores.get)
        score = scores[label]
        if _looks_false_positive(name, state, fp_vector):
            continue
        tokens = set(_tokens(name))
        same_file = node.get("file")
        token_hit = ""
        for token in tokens:
            if len(token) >= 6 and token in shared.get(label, set()):
                token_hit = token
                break
        if token_hit == "" and score < state.threshold(label):
            continue
        if token_hit == "" and scores[label] - sorted(scores.values())[-2] < 0.06:
            continue
        rule, theme, title, exposure, privilege, asset, exploit = CLASS_RULE[label]
        reason = f"shares the token '{token_hit}'" if token_hit else f"score {score:.2f}"
        evidence = f"Learned from this repository: {name} {reason} with the {label} names already confirmed here."
        model.observe(
            rule=rule,
            theme=theme,
            title=title,
            stage="review",
            node_id=node["id"],
            file=node.get("file"),
            line=node.get("line"),
            evidence=evidence,
            recommendation=rule_recommendation(rule),
            exposure=exposure,
            privilege=privilege,
            asset=asset,
            exploitability=exploit,
            identity=False,
            learned=True,
        )
        seen.add(key)
        promoted.append({"name": name, "file": node.get("file"), "label": label, "score": round(score, 3)})
        if len(promoted) >= MAX_PROMOTED:
            break
    return promoted


def _confirmed(model: RepoModel) -> list[tuple[str, str]]:
    mapping = {
        "credential": "credential",
        "rce": "execution",
        "sqli": "query",
        "ssrf": "egress",
        "unauthenticated": "privileged",
        "authz": "privileged",
    }
    found = []
    nodes = model.nodes
    for item in model.observations:
        label = mapping.get(item.get("theme") or "")
        if not label:
            continue
        node = nodes.get(item.get("node_id") or "")
        if node and node.get("name"):
            found.append((label, node["name"]))
        evidence = item.get("evidence") or ""
        if evidence:
            found.append((label, evidence[:80]))
    return found


def _contextual(model: RepoModel, confirmed: list[tuple[str, str]]) -> list[tuple[str, str]]:
    by_file: dict[str, set[str]] = defaultdict(set)
    for label, text in confirmed:
        for token in _tokens(text):
            if len(token) >= 6:
                by_file[label].add(token)
    extra = []
    for node in model.nodes.values():
        name = node.get("name") or ""
        for label, tokens in by_file.items():
            if any(token in _tokens(name) for token in tokens):
                extra.append((label, name))
    for sample in getattr(model, "samples", []) or []:
        name = sample.get("text") or ""
        for label, tokens in by_file.items():
            if any(token in _tokens(name) for token in tokens):
                extra.append((label, name))
    return extra


def _languages(model: RepoModel) -> dict[str, int]:
    counts: dict[str, int] = {}
    for node in model.nodes.values():
        language = node.get("language")
        if language:
            counts[language] = counts.get(language, 0) + 1
    return counts


def _tokens(text: str) -> list[str]:
    found = []
    for part in re.findall(r"[A-Za-z][A-Za-z0-9_]{2,}", text or ""):
        for piece in re.split(r"_", part):
            if len(piece) >= 3:
                found.append(piece.lower())
        for piece in re.findall(r"[A-Z]?[a-z0-9]{3,}|[A-Z]{3,}", part):
            found.append(piece.lower())
    return found


def _bucket(gram: str) -> int:
    digest = hashlib.sha1(gram.encode()).hexdigest()
    return int(digest[:8], 16) % DIM


def _cosine(left: list[float], right: list[float]) -> float:
    return sum(a * b for a, b in zip(left, right))


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save(path: Path, payload: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError:
        return

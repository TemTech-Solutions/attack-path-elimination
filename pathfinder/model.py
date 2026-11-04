from __future__ import annotations

import hashlib
from pathlib import Path


FOLLOW_EDGES = {
    "CALLS",
    "ROUTES_TO",
    "READS",
    "WRITES",
    "FLOWS_TO",
    "USES_SECRET",
    "DEPLOYS",
    "INVOKES",
    "TRUSTS",
    "CONTAINS",
}


class RepoModel:
    """In-memory property graph. Neo4j is an export target, not a runtime requirement."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self.observations: list[dict] = []
        self.parse_errors: list[dict] = []
        self._unique: dict[tuple[str, str], str] = {}
        self._edge_seen: set[tuple[str, str, str]] = set()

    def rel(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()

    def node(
        self,
        kind: str,
        name: str,
        *,
        file: str | None = None,
        line: int | None = None,
        lane: str = "other",
        language: str | None = None,
        unique: bool = False,
        properties: dict | None = None,
        receives: str | None = None,
    ) -> str:
        properties = dict(properties or {})
        if unique:
            key = (kind, name)
            existing = self._unique.get(key)
            if existing:
                self._merge(existing, file, line, properties, receives, lane)
                return existing
        identity = f"{kind}|{name}|{file}|{line}|{len(self.nodes)}"
        node_id = hashlib.sha1(identity.encode()).hexdigest()[:16]
        self.nodes[node_id] = {
            "id": node_id,
            "kind": kind,
            "name": name,
            "component": name,
            "language": language,
            "file": file,
            "line": line,
            "lane": lane,
            "calls": [],
            "receives": receives,
            "properties": properties,
        }
        if unique:
            self._unique[(kind, name)] = node_id
        return node_id

    def _merge(self, node_id: str, file, line, properties, receives, lane) -> None:
        current = self.nodes[node_id]
        if current.get("file") is None and file:
            current["file"] = file
            current["line"] = line
        if receives and not current.get("receives"):
            current["receives"] = receives
        if lane and current.get("lane") in {None, "other"}:
            current["lane"] = lane
        merged = current["properties"]
        for key, value in properties.items():
            if key not in merged or merged[key] in (None, False, "", []):
                merged[key] = value
            elif value is True:
                merged[key] = True

    def edge(
        self,
        source: str,
        target: str,
        kind: str,
        *,
        file: str | None = None,
        line: int | None = None,
        evidence: str = "",
        confidence: str = "EXTRACTED",
    ) -> None:
        if not source or not target or source == target:
            return
        key = (source, target, kind)
        if key in self._edge_seen:
            return
        self._edge_seen.add(key)
        self.edges.append(
            {
                "source": source,
                "target": target,
                "kind": kind,
                "file": file,
                "line": line,
                "evidence": _clip(evidence),
                "confidence": "INFERRED" if confidence == "INFERRED" else "EXTRACTED",
            }
        )
        if kind == "CALLS":
            calls = self.nodes[source]["calls"]
            target_name = self.nodes[target]["name"]
            if target_name not in calls:
                calls.append(target_name)

    def observe(self, **observation) -> None:
        from pathfinder.baseline import rule_family, rule_tier

        observation["evidence"] = _clip(observation.get("evidence", ""))
        observation.setdefault("family", rule_family(str(observation.get("rule") or "")))
        observation.setdefault("tier", rule_tier(str(observation.get("rule") or "")))
        observation["id"] = hashlib.sha1(
            f"{observation.get('rule')}|{observation.get('file')}|{observation.get('line')}|{observation.get('title')}".encode()
        ).hexdigest()[:12]
        self.observations.append(observation)

    def error(self, file: str, message: str) -> None:
        self.parse_errors.append({"file": file, "message": message[:300]})

    def children(self) -> dict[str, list[str]]:
        graph: dict[str, list[str]] = {node_id: [] for node_id in self.nodes}
        for edge in self.edges:
            if edge["kind"] in FOLLOW_EDGES:
                graph.setdefault(edge["source"], []).append(edge["target"])
        return graph


def _clip(text: str, limit: int = 220) -> str:
    clean = " ".join(str(text).split())
    if len(clean) <= limit:
        return clean
    return clean[: limit - 1] + "…"

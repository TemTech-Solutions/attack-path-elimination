"""Map the attack graph the way a code knowledge graph is mapped.

Every edge is EXTRACTED when the relationship is written in a file, or
INFERRED when this analyzer resolved it. A path's confidence is its weakest
hop. Communities and god nodes are computed locally. No embeddings.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path


SCHEMA_VERSION = 1


def attach_graph(result: dict) -> dict:
    result["graph"] = build_graph(result)
    return result


def build_graph(result: dict) -> dict:
    nodes = result.get("nodes") or []
    edges = result.get("edges") or []
    degree = Counter()
    for edge in edges:
        edge.setdefault("confidence", "EXTRACTED")
        degree[edge["source"]] += 1
        degree[edge["target"]] += 1
    communities, membership = _communities(nodes, edges, degree)
    by_id = {node["id"]: node for node in nodes}
    god = [
        {
            "id": node_id,
            "name": by_id[node_id]["name"],
            "kind": by_id[node_id]["kind"],
            "degree": degree[node_id],
            "community": membership.get(node_id, {}).get("label", ""),
        }
        for node_id, _count in degree.most_common(8)
        if node_id in by_id and degree[node_id] > 0
    ]
    view_nodes = []
    for node in nodes:
        group = membership.get(node["id"], {})
        view_nodes.append(
            {
                "id": node["id"],
                "name": node["name"],
                "kind": node["kind"],
                "file": node.get("file"),
                "line": node.get("line"),
                "risk": node.get("risk") or 0,
                "degree": degree[node["id"]],
                "community": group.get("id"),
                "community_label": group.get("label") or node["kind"],
            }
        )
    view_edges = [
        {
            "source": edge["source"],
            "target": edge["target"],
            "relation": edge["kind"],
            "confidence": edge.get("confidence") or "EXTRACTED",
            "evidence": edge.get("evidence") or "",
            "file": edge.get("file"),
            "line": edge.get("line"),
        }
        for edge in edges
    ]
    _annotate_paths(result.get("paths") or [], edges)
    return {
        "schema_version": SCHEMA_VERSION,
        "principle": "Each edge is EXTRACTED or INFERRED. Path confidence is the weakest hop.",
        "nodes": view_nodes,
        "edges": view_edges,
        "communities": communities,
        "god_nodes": god,
    }


def render_graph_html(result: dict) -> str:
    import json

    template = (Path(__file__).parent / "templates" / "graph.html").read_text(encoding="utf-8")
    graph = result.get("graph") or build_graph(result)
    payload = {
        "repository": result.get("repository"),
        "graph": graph,
        "paths": [
            {
                "id": path["id"],
                "category": path["category"],
                "band": path["band"],
                "score": path["score"],
                "confidence": path.get("confidence") or "INFERRED",
                "narrative": path["narrative"],
                "node_ids": path.get("node_ids") or [],
                "edges": path.get("graph_edges") or [],
            }
            for path in result.get("paths") or []
        ],
    }
    encoded = json.dumps(payload, ensure_ascii=False).replace("<", "\\u003c")
    return template.replace("__PAYLOAD__", encoded)


def render_graph_report(result: dict) -> str:
    graph = result.get("graph") or {}
    lines = [
        f"# {result.get('repository') or 'Repository'} attack graph",
        "",
        "Each edge is EXTRACTED when the relationship is written in a source file, and INFERRED when the analyzer resolved it across files or runtime configuration. A path's confidence is its weakest hop.",
        "",
        "## God nodes",
        "",
    ]
    gods = graph.get("god_nodes") or []
    if not gods:
        lines.append("No connected component in this snapshot.")
    for node in gods:
        lines.append(f"- {node['name']} ({node['kind']}) degree {node['degree']} in {node['community']}")
    lines.extend(["", "## Communities", ""])
    for community in graph.get("communities") or []:
        lines.append(f"- {community['label']} · {community['size']} nodes")
    lines.extend(["", "## Paths", ""])
    for path in result.get("paths") or []:
        lines.append(
            f"### {path['band']} {path['score']} {path['category']} · {path.get('confidence', 'INFERRED')}"
        )
        lines.append("")
        lines.append(path["narrative"])
        lines.append("")
        for edge in path.get("graph_edges") or []:
            lines.append(
                f"- {edge['source'][:8]} --{edge['kind']}--> {edge['target'][:8]} [{edge['confidence']}] {edge.get('evidence', '')}".rstrip()
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _annotate_paths(paths: list[dict], edges: list[dict]) -> None:
    index: dict[str, list[dict]] = defaultdict(list)
    for edge in edges:
        index[edge["source"]].append(edge)
    for path in paths:
        sequence = []
        for node_id in path.get("node_ids") or []:
            if node_id and (not sequence or sequence[-1] != node_id):
                sequence.append(node_id)
        walked = []
        gap = False
        for start, goal in zip(sequence, sequence[1:]):
            steps = _shortest(index, start, goal)
            if not steps:
                gap = True
                continue
            walked.extend(steps)
        unique = []
        seen = set()
        for edge in walked:
            key = (edge["source"], edge["target"], edge["kind"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(
                {
                    "source": edge["source"],
                    "target": edge["target"],
                    "kind": edge["kind"],
                    "confidence": edge.get("confidence") or "EXTRACTED",
                    "evidence": edge.get("evidence") or "",
                }
            )
        inferred = gap or not unique or any(item["confidence"] == "INFERRED" for item in unique)
        path["confidence"] = "INFERRED" if inferred else "EXTRACTED"
        path["graph_edges"] = unique


def _shortest(index: dict[str, list[dict]], start: str, goal: str) -> list[dict]:
    if not start or not goal or start == goal:
        return []
    queue = [(start, [])]
    seen = {start}
    while queue:
        current, trail = queue.pop(0)
        for edge in index.get(current, []):
            nxt = edge["target"]
            if nxt in seen:
                continue
            step = trail + [edge]
            if nxt == goal:
                return step
            seen.add(nxt)
            queue.append((nxt, step))
    return []


def _communities(nodes: list[dict], edges: list[dict], degree: Counter) -> tuple[list[dict], dict]:
    ids = [node["id"] for node in nodes]
    by_id = {node["id"]: node for node in nodes}
    adjacent = {node_id: set() for node_id in ids}
    for edge in edges:
        source, target = edge["source"], edge["target"]
        if source in adjacent and target in adjacent and source != target:
            adjacent[source].add(target)
            adjacent[target].add(source)
    labels = {node_id: node_id for node_id in ids}
    ordered = sorted(ids)
    for _ in range(12):
        nxt = dict(labels)
        changed = False
        for node_id in ordered:
            if not adjacent[node_id]:
                continue
            counts: dict[str, int] = {}
            for neighbor in adjacent[node_id]:
                label = labels[neighbor]
                counts[label] = counts.get(label, 0) + 1
            best = max(counts, key=lambda label: (counts[label], label))
            if nxt[node_id] != best:
                nxt[node_id] = best
                changed = True
        labels = nxt
        if not changed:
            break
    groups: dict[str, list[str]] = {}
    for node_id in ids:
        groups.setdefault(labels[node_id], []).append(node_id)
    communities = []
    membership = {}
    ordered_groups = sorted(groups.values(), key=lambda members: min(members))
    for index, members in enumerate(ordered_groups, start=1):
        god = max(members, key=lambda node_id: (degree[node_id], node_id))
        label = by_id[god]["name"]
        communities.append({"id": index, "label": label, "size": len(members), "god_node": god})
        for member in members:
            membership[member] = {"id": index, "label": label}
    return communities, membership

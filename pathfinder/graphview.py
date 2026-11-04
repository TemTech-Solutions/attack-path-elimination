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
    findings: dict[str, list[dict]] = defaultdict(list)
    for item in result.get("observations") or []:
        node_id = item.get("node_id")
        if not node_id:
            continue
        findings[node_id].append(
            {
                "rule": item.get("rule") or "",
                "title": item.get("title") or "",
                "evidence": item.get("evidence") or "",
                "recommendation": item.get("recommendation") or "",
                "file": item.get("file"),
                "line": item.get("line"),
            }
        )
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
                "language": node.get("language"),
                "community": group.get("id"),
                "community_label": group.get("label") or node["kind"],
                "findings": findings.get(node["id"]) or [],
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
    paths = elimination_paths(result)
    languages = sorted({node.get("language") for node in graph.get("nodes") or [] if node.get("language")})
    payload = {
        "repository": result.get("repository"),
        "graph": graph,
        "paths": paths,
        "languages": languages,
        "adaptation": result.get("adaptation") or {},
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


def elimination_paths(result: dict) -> list[dict]:
    """Every chain the report says to delete, including objective searches."""
    edges = result.get("edges") or []
    packed = []
    seen = set()
    for path in result.get("paths") or []:
        item = _pack_composed(path)
        key = (item["narrative"], tuple(item["node_ids"]))
        if key in seen:
            continue
        seen.add(key)
        packed.append(item)
    for hypothesis in result.get("hypotheses") or []:
        name = hypothesis.get("name") or "Objective"
        for path in hypothesis.get("paths") or []:
            item = _pack_objective(name, path)
            key = (item["narrative"], tuple(item["node_ids"]))
            if key in seen:
                continue
            seen.add(key)
            packed.append(item)
    _annotate_paths(packed, edges)
    for item in packed:
        item["edges"] = item.get("graph_edges") or []
        item.pop("graph_edges", None)
        item["diagnosis"] = _diagnosis(item)
        item["next_steps"] = _next_steps(item)
        item["kind"] = "path"
    packed.extend(_finding_issues(result, packed))
    packed.sort(key=lambda item: (-item["score"], item["category"], item["narrative"]))
    return packed


def _pack_composed(path: dict) -> dict:
    hops = []
    for hop in path.get("hops") or []:
        hops.append(
            {
                "label": hop.get("label") or "",
                "node_id": hop.get("node_id"),
                "rule": hop.get("rule") or "",
                "file": hop.get("file"),
                "line": hop.get("line"),
                "evidence": hop.get("evidence") or "",
                "recommendation": hop.get("recommendation") or "",
            }
        )
    return {
        "id": path.get("id"),
        "category": path.get("category") or "",
        "band": path.get("band") or "",
        "score": path.get("score") or 0,
        "confidence": path.get("confidence") or "INFERRED",
        "narrative": path.get("narrative") or "",
        "node_ids": list(path.get("node_ids") or []),
        "hops": hops,
        "remove": list(path.get("recommendations") or []),
        "edges": list(path.get("graph_edges") or []),
    }


def _pack_objective(name: str, path: dict) -> dict:
    labels = path.get("labels") or []
    narrative = "An attacker can move from " + " → ".join(labels) + "." if labels else name
    hops = []
    for hop in path.get("hops") or []:
        hops.append(
            {
                "label": hop.get("label") or "",
                "node_id": hop.get("node_id"),
                "rule": "",
                "file": hop.get("file"),
                "line": hop.get("line"),
                "evidence": "",
                "recommendation": "",
            }
        )
    remove = list(path.get("remove") or [])
    for note in path.get("notes") or []:
        text = note.get("remove") or note.get("detail")
        if text and text not in remove:
            remove.append(text)
    return {
        "id": path.get("id") or name,
        "category": name,
        "band": path.get("band") or "",
        "score": path.get("score") or 0,
        "confidence": "INFERRED",
        "narrative": narrative,
        "node_ids": list(path.get("node_ids") or []),
        "hops": hops,
        "remove": remove,
        "edges": [],
    }


def _diagnosis(item: dict) -> str:
    narrative = item.get("narrative") or ""
    hops = item.get("hops") or []
    if len(hops) >= 2:
        start = hops[0]
        end = hops[-1]
        return (
            f"{narrative} The clear path starts at {start.get('label') or 'the entry'}"
            f" ({_place(start)}) and ends at {end.get('label') or 'the last hop'} ({_place(end)}). "
            f"Confidence is {item.get('confidence') or 'INFERRED'}, the weakest hop on this walk."
        )
    if hops:
        hop = hops[0]
        return f"{hop.get('label') or 'Finding'}. {hop.get('evidence') or narrative} Recorded at {_place(hop)}."
    return narrative


def _next_steps(item: dict) -> list[dict]:
    hops = item.get("hops") or []
    remove = list(item.get("remove") or [])
    if not remove:
        remove = [hop.get("recommendation") for hop in hops if hop.get("recommendation")]
    steps = []
    used: set[int] = set()
    for text in remove:
        match = None
        for index, hop in enumerate(hops):
            recommendation = hop.get("recommendation") or ""
            if index in used or not recommendation:
                continue
            if recommendation == text or recommendation in text:
                match = hop
                used.add(index)
                break
        steps.append(
            {
                "order": len(steps) + 1,
                "action": text,
                "file": (match or {}).get("file"),
                "line": (match or {}).get("line"),
                "hop": (match or {}).get("label") or "",
                "node_id": (match or {}).get("node_id"),
            }
        )
    return steps


def _finding_issues(result: dict, paths: list[dict]) -> list[dict]:
    covered = set()
    for path in paths:
        for hop in path.get("hops") or []:
            covered.add((hop.get("rule") or "", hop.get("file"), hop.get("line")))
    issues = []
    for finding in result.get("findings") or []:
        key = (finding.get("rule") or "", finding.get("file"), finding.get("line"))
        if key in covered:
            continue
        covered.add(key)
        hop = {
            "label": finding.get("title") or "Finding",
            "node_id": finding.get("node_id"),
            "rule": finding.get("rule") or "",
            "file": finding.get("file"),
            "line": finding.get("line"),
            "evidence": finding.get("evidence") or "",
            "recommendation": finding.get("recommendation") or "",
        }
        narrative = f"{hop['label']}. {hop['evidence']}".strip()
        item = {
            "id": finding.get("id") or key,
            "category": finding.get("theme") or "review",
            "band": finding.get("band") or "Low",
            "score": finding.get("score") or 0,
            "confidence": "EXTRACTED",
            "narrative": narrative,
            "node_ids": [finding["node_id"]] if finding.get("node_id") else [],
            "hops": [hop],
            "remove": [hop["recommendation"]] if hop["recommendation"] else [],
            "edges": [],
            "kind": "finding",
        }
        item["diagnosis"] = _diagnosis(item)
        item["next_steps"] = _next_steps(item)
        issues.append(item)
    return issues


def _place(hop: dict) -> str:
    if not hop or not hop.get("file"):
        return "resolved from the graph"
    if hop.get("line"):
        return f"{hop['file']}:{hop['line']}"
    return str(hop["file"])


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
                    "file": edge.get("file"),
                    "line": edge.get("line"),
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

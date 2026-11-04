from __future__ import annotations

import json
from pathlib import Path

from pathfinder.graphview import render_graph_html, render_graph_report
from pathfinder.threatmodel import render_threat_html


def render_html(result: dict) -> str:
    template_path = Path(__file__).parent / "templates" / "report.html"
    template = template_path.read_text(encoding="utf-8")
    payload = json.dumps(result, ensure_ascii=False).replace("<", "\\u003c")
    return template.replace("__PAYLOAD__", payload)


def pr_comment(result: dict) -> str:
    lines = ["### Attack-path review", ""]
    hot = [path for path in result["paths"] if path["band"] in {"Critical", "High"}]
    if not hot:
        lines.append("No critical or high composed attack path in this snapshot.")
        lines.append("")
    for path in hot[:5]:
        lines.append(f"⚠ {path['band']} attack path · score {path['score']}")
        lines.append("")
        lines.append(path["narrative"])
        lines.append("")
        for hop in path["hops"]:
            location = f"`{hop['file']}:{hop['line']}`" if hop.get("file") else ""
            lines.append(f"- {hop['label']} {location}".rstrip())
        lines.append("")
        for recommendation in path["recommendations"][:3]:
            lines.append(f"- Remove: {recommendation}")
        lines.append("")
    per = result.get("per") or {}
    lines.append(
        f"Path erasure rate {per.get('rate', 0)} = {per.get('erased', 0)} erased / {per.get('eligible', 0)} eligible."
    )
    lines.append("")
    reached = [item for item in result.get("hypotheses") or [] if item.get("found")]
    if reached:
        lines.append("### Objectives an attacker can reach")
        lines.append("")
        for item in reached[:6]:
            top = item["paths"][0]
            lines.append(f"- {item['name']}: {item['found']} path(s), {top['band']} — {' → '.join(top['labels'][:6])}")
        lines.append("")
    lines.append("Static review only. The change to make is deletion or constraint of the path, not a new alert.")
    return "\n".join(lines)


def to_cypher(result: dict) -> str:
    lines = [
        "// Attack graph export. Load into Neo4j only after review.",
        "// Nodes are components. Edges are the relationships the analyzer could prove from the repository.",
    ]
    for node in result["nodes"]:
        label = "".join(char for char in node["kind"].title() if char.isalnum()) or "Node"
        lines.append(
            "MERGE (n:%s {id: %s}) SET n.name = %s, n.file = %s, n.line = %s, n.risk = %s;"
            % (
                label,
                _cypher(node["id"]),
                _cypher(node["name"]),
                _cypher(node.get("file") or ""),
                int(node.get("line") or 0),
                int(node.get("risk") or 0),
            )
        )
    for edge in result["edges"]:
        kind = "".join(char for char in edge["kind"] if char.isalnum() or char == "_") or "RELATED"
        lines.append(
            "MATCH (a {id: %s}), (b {id: %s}) MERGE (a)-[:%s]->(b);"
            % (_cypher(edge["source"]), _cypher(edge["target"]), kind)
        )
    return "\n".join(lines) + "\n"


def write_outputs(result: dict, directory: Path) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    html_path = directory / "report.html"
    graph_path = directory / "graph.html"
    threat_path = directory / "threat-model.html"
    report_path = directory / "graph-report.md"
    json_path = directory / "graph.json"
    comment_path = directory / "pr-comment.md"
    cypher_path = directory / "graph.cypher"
    html_path.write_text(render_html(result), encoding="utf-8")
    graph_path.write_text(render_graph_html(result), encoding="utf-8")
    threat_path.write_text(render_threat_html(result), encoding="utf-8")
    report_path.write_text(render_graph_report(result), encoding="utf-8")
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    comment_path.write_text(pr_comment(result), encoding="utf-8")
    cypher_path.write_text(to_cypher(result), encoding="utf-8")
    return {
        "html": html_path,
        "graph": graph_path,
        "threat": threat_path,
        "report": report_path,
        "json": json_path,
        "comment": comment_path,
        "cypher": cypher_path,
    }


def _cypher(value: str) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"

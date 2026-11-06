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
    """Work queue for a pipeline log. Critical, high, and a short set of medium walks."""
    scorecard = result.get("scorecard") or {}
    paths = list(result.get("paths") or [])
    findings = list(result.get("findings") or [])
    critical = [path for path in paths if path.get("band") == "Critical"]
    high = [path for path in paths if path.get("band") == "High"]
    medium = [path for path in paths if path.get("band") == "Medium"][:5]
    shown = critical + high + medium
    covered = set()
    for path in shown:
        for hop in path.get("hops") or []:
            covered.add((hop.get("rule") or "", hop.get("file"), hop.get("line")))
    extra = []
    medium_findings = []
    for finding in findings:
        key = (finding.get("rule") or "", finding.get("file"), finding.get("line"))
        if key in covered:
            continue
        band = finding.get("band")
        if band in {"Critical", "High"}:
            extra.append(finding)
        elif band == "Medium" and (finding.get("score") or 0) >= 55:
            medium_findings.append(finding)
    extra = extra[:12] + medium_findings[:5]
    lines = ["### Attack-path review", ""]
    lines.append(
        f"Reviewed {scorecard.get('components', 0)} components and {scorecard.get('findings', len(findings))} findings. "
        "The work queue is critical, high, and the medium walks that connect an entry to an asset. "
        "The HTML artifact keeps the full review."
    )
    lines.append("")
    lines.append(f"- Critical paths: {len(critical)}")
    lines.append(f"- High paths: {len(high)}")
    lines.append(f"- Medium paths shown: {len(medium)}")
    lines.append("")
    if not critical and not high:
        lines.append("No critical or high composed attack path in this snapshot.")
        lines.append("")
    for path in shown:
        lines.extend(_path_block(path))
    lines.extend(_threat_lines(result, covered))
    if extra:
        lines.append("### Component findings")
        lines.append("")
        for finding in extra:
            place = f"`{finding.get('file')}:{finding.get('line')}`" if finding.get("file") else ""
            title = finding.get("title") or finding.get("rule") or "Finding"
            evidence = finding.get("evidence") or ""
            lines.append(f"- **{finding.get('band')} {finding.get('score')}** {finding.get('rule') or ''} {title} {place}".rstrip())
            if evidence:
                lines.append(f"  - {evidence}")
            if finding.get("recommendation"):
                lines.append(f"  - Remove: {finding['recommendation']}")
        lines.append("")
    per = result.get("per") or {}
    lines.append(
        f"Path erasure rate {per.get('rate', 0)} = {per.get('erased', 0)} erased / {per.get('eligible', 0)} eligible."
    )
    lines.append("")
    reached = []
    for item in result.get("hypotheses") or []:
        if not item.get("found"):
            continue
        top = item["paths"][0]
        if top.get("band") not in {"Critical", "High", "Medium"}:
            continue
        reached.append(item)
    if reached:
        lines.append("### Objectives an attacker can reach")
        lines.append("")
        for item in reached[:8]:
            top = item["paths"][0]
            lines.append(f"- {item['name']}: {item['found']} path(s), {top['band']} — {' → '.join(top['labels'][:6])}")
        lines.append("")
    lines.append("Open `report.html`, `graph.html`, and `threat-model.html` in the attack-path-report artifact for the full review.")
    lines.append("")
    lines.append("Static review only. The change to make is deletion or constraint of the path, not a new alert.")
    suppressed = result.get("suppressed") or []
    if suppressed:
        lines.append("")
        lines.append(f"{len(suppressed)} finding(s) omitted by remediation false-positive exceptions.")
    scan = result.get("exception_scan") or {}
    if scan:
        lines.append("")
        lines.append(
            f"Exception scan removed {scan.get('removed', 0)} published finding(s) recorded in pathfinder-exceptions.yml."
        )
        for note in scan.get("notes") or []:
            lines.append(f"- {note}")
    return "\n".join(lines)


def pipeline_annotations(result: dict) -> list[str]:
    """One-line file annotations for GitHub Actions and Azure Pipelines."""
    import os

    github = os.environ.get("GITHUB_ACTIONS") == "true"
    azure = os.environ.get("TF_BUILD", "").lower() == "true"
    if not github and not azure:
        return []
    notes = []
    for path in [item for item in result.get("paths") or [] if item.get("band") in {"Critical", "High"}]:
        notes.append(_annotate(path.get("band"), path.get("score"), path.get("narrative") or "", path.get("hops") or [], path.get("recommendations") or [], github))
    for path in [item for item in result.get("paths") or [] if item.get("band") == "Medium"][:5]:
        notes.append(_annotate(path.get("band"), path.get("score"), path.get("narrative") or "", path.get("hops") or [], path.get("recommendations") or [], github))
    seen = {(hop.get("file"), hop.get("line")) for path in (result.get("paths") or []) for hop in (path.get("hops") or [])}
    from pathfinder.threatmodel import build_threat_model

    extra = 0
    for threat in build_threat_model(result).get("threats") or []:
        if threat.get("band") not in {"Critical", "High"}:
            continue
        hop = next((item for item in threat.get("hops") or [] if item.get("file")), None)
        if hop is None or (hop.get("file"), hop.get("line")) in seen:
            continue
        seen.add((hop.get("file"), hop.get("line")))
        notes.append(
            _annotate(
                threat.get("band"),
                threat.get("score"),
                _threat_message(threat),
                threat.get("hops") or [],
                [threat["recommendation"]] if threat.get("recommendation") else [],
                github,
            )
        )
        extra += 1
        if extra >= 8:
            break
    return [line for line in notes if line]


def _threat_lines(result: dict, covered: set) -> list[str]:
    from pathfinder.threatmodel import build_threat_model

    modeled = build_threat_model(result)
    summary = modeled.get("summary") or {}
    queued = []
    medium = []
    for threat in modeled.get("threats") or []:
        hop = next((item for item in threat.get("hops") or [] if item.get("file")), None)
        if hop is None:
            continue
        key = (hop.get("rule") or "", hop.get("file"), hop.get("line"))
        if key in covered:
            continue
        band = threat.get("band")
        if band in {"Critical", "High"}:
            queued.append(threat)
        elif band == "Medium" and (threat.get("score") or 0) >= 55:
            medium.append(threat)
    shown = queued[:12] + medium[:5]
    lines = ["### Threat model", ""]
    lines.append(
        f"Threat model: {summary.get('threats', 0)} issues, {summary.get('critical', 0)} critical, "
        f"{summary.get('frameworks', 0)} frameworks matched. "
        "The queue below is critical, high, and a few medium issues that are not already listed as attack-path hops."
    )
    lines.append("")
    if not shown:
        lines.append("No additional threat-model issue outside the walks above.")
        lines.append("")
        return lines
    for threat in shown:
        hop = next(item for item in threat.get("hops") or [] if item.get("file"))
        place = f"`{hop.get('file')}:{hop.get('line')}`"
        stride = ", ".join(threat.get("stride") or []) or "unspecified"
        frameworks = ", ".join((threat.get("frameworks") or [])[:4])
        title = threat.get("name") or "Threat"
        lines.append(f"- **{threat.get('band')} {threat.get('score')}** {title} {place}".rstrip())
        lines.append(f"  - STRIDE: {stride}")
        if frameworks:
            lines.append(f"  - Frameworks: {frameworks}")
        if hop.get("evidence"):
            lines.append(f"  - {hop['evidence']}")
        if threat.get("effect"):
            lines.append(f"  - {threat['effect']}")
        if threat.get("recommendation"):
            lines.append(f"  - Remove: {threat['recommendation']}")
    lines.append("")
    return lines


def _threat_message(threat: dict) -> str:
    stride = ", ".join(threat.get("stride") or [])
    text = threat.get("name") or "Threat"
    if stride:
        text = f"{text}. STRIDE: {stride}."
    if threat.get("effect"):
        text = f"{text} {threat['effect']}"
    return text


def _path_block(path: dict) -> list[str]:
    lines = [f"### {path.get('band')} · {path.get('score')} · {str(path.get('category') or '').replace('_', ' ')}", ""]
    if path.get("narrative"):
        lines.append(path["narrative"])
        lines.append("")
    for index, hop in enumerate(path.get("hops") or [], start=1):
        place = f"`{hop['file']}:{hop['line']}`" if hop.get("file") else "resolved from the graph"
        lines.append(f"{index}. {hop.get('label') or 'Hop'} · {place}")
        if hop.get("evidence"):
            lines.append(f"   - {hop['evidence']}")
    if path.get("hops"):
        lines.append("")
    for recommendation in (path.get("recommendations") or [])[:3]:
        lines.append(f"- Remove: {recommendation}")
    lines.append("")
    return lines


def _annotate(band: str, score, narrative: str, hops: list, recommendations: list, github: bool) -> str:
    hop = next((item for item in hops if item.get("file")), None)
    if hop is None:
        return ""
    file_name = str(hop.get("file") or "").replace(",", " ")
    line = int(hop.get("line") or 1)
    message = " ".join(str(narrative or "").split())
    if recommendations:
        message = f"{message} Remove: {' '.join(str(recommendations[0]).split())}"
    message = message.replace("\n", " ")[:500]
    title = f"{band} {score}".strip()
    if github:
        level = {"Critical": "error", "High": "warning"}.get(band or "", "notice")
        return f"::{level} file={file_name},line={line},title={title}::{message}"
    level = "error" if band == "Critical" else "warning"
    return f"##vso[task.logissue type={level};sourcepath={file_name};linenumber={line};code={title}]{message}"


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

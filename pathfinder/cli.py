from __future__ import annotations

import argparse
import json
from pathlib import Path

from pathfinder.analyze import analyze, apply_history
from pathfinder.exceptions import EXCEPTIONS_FILE, load_exceptions, record_exception
from pathfinder.install import PUBLIC_REF, InstallError, install
from pathfinder.query import (
    FRAMEWORKS,
    QueryError,
    builtin_hypotheses,
    format_hypotheses,
    hypothesis_by_name,
    load_rule_file,
    normalize,
    parse_graph_query,
    search,
    translate,
)
from pathfinder.report import pr_comment, write_outputs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compose repository attack paths and answer a specific attacker objective.")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (
        ("analyze", "Analyze a local repository"),
        ("scan", "Analyze a local repository"),
    ):
        scan_parser = sub.add_parser(name, help=help_text)
        scan_parser.add_argument("target", type=Path)
        scan_parser.add_argument("--out", type=Path, default=Path("out"))

    comment_parser = sub.add_parser("comment", help="Print a pull-request comment for a repository")
    comment_parser.add_argument("target", type=Path)

    serve_parser = sub.add_parser("serve", help="Serve the latest HTML report")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8080)
    serve_parser.add_argument("--report", type=Path, default=Path("out"))

    install_parser = sub.add_parser("install", help="Add a CI hook to another repository")
    install_parser.add_argument("target", type=Path, help="Root of the application repository")
    install_parser.add_argument("--platform", choices=("github", "gitlab"), default="github")
    install_parser.add_argument("--tool", help="owner/repository or https://github.com/owner/repository")
    install_parser.add_argument("--ref", default=PUBLIC_REF, help="Full commit SHA of this action")
    install_parser.add_argument("--force", action="store_true")

    find_parser = sub.add_parser("find-path", help="Ask whether an attacker can get from one role to another")
    find_parser.add_argument("target", type=Path)
    find_parser.add_argument("--from", dest="start", required=True, help="Start role, for example public-endpoint or internet")
    find_parser.add_argument("--to", dest="goal", required=True, help="Target role, for example secret, pii-database, or iam-admin")
    find_parser.add_argument("--through", default="", help="Comma-separated roles the walk must pass, in order")
    find_parser.add_argument("--condition", action="append", default=[], help="Condition that must hold, such as no_authz_check")
    find_parser.add_argument("--must-not-have", action="append", default=[], dest="must_not_have")
    find_parser.add_argument("--max-hops", type=int, default=12)
    find_parser.add_argument("--out", type=Path)

    simulate_parser = sub.add_parser("simulate", help="Run a hypothesis file against a repository")
    simulate_parser.add_argument("target", type=Path)
    simulate_parser.add_argument("rule", type=Path)
    simulate_parser.add_argument("--out", type=Path)

    hunt_parser = sub.add_parser("hunt", help="Run one kill-chain template, or all of them")
    hunt_parser.add_argument("target", type=Path)
    hunt_parser.add_argument("name", nargs="?", help="Template name, for example credentials or ransomware")
    hunt_parser.add_argument("--out", type=Path)

    sub.add_parser("hunts", help="List kill-chain templates")
    sub.add_parser("frameworks", help="List the threat-model frameworks every scan reviews")

    except_parser = sub.add_parser("except", help="Record a remediation false positive so later scans ignore that case")
    except_parser.add_argument("target", type=Path)
    except_parser.add_argument("--rule", required=True)
    except_parser.add_argument("--file", required=True)
    except_parser.add_argument("--line", type=int, required=True)
    except_parser.add_argument("--reason", required=True)
    except_parser.add_argument("--by", default="remediation")

    list_parser = sub.add_parser("exceptions", help="List false-positive exceptions recorded for a repository")
    list_parser.add_argument("target", type=Path)

    ask_parser = sub.add_parser("ask", help="Turn a plain question into a start and a target")
    ask_parser.add_argument("target", type=Path)
    ask_parser.add_argument("question")
    ask_parser.add_argument("--out", type=Path)

    query_parser = sub.add_parser("query", help="Run a short graph query such as PUBLIC_ENDPOINT -[*..12]-> SECRET")
    query_parser.add_argument("target", type=Path)
    query_parser.add_argument("expression")
    query_parser.add_argument("--out", type=Path)

    graph_parser = sub.add_parser("graph", help="Analyze and print the graph summary")
    graph_parser.add_argument("target", type=Path)
    graph_parser.add_argument("--out", type=Path, default=Path("out"))

    export_parser = sub.add_parser("export", help="Analyze and write html, json, or cypher")
    export_parser.add_argument("target", type=Path)
    export_parser.add_argument("fmt", nargs="?", default="html", choices=("html", "json", "cypher"))
    export_parser.add_argument("--out", type=Path, default=Path("out"))

    init_parser = sub.add_parser("init", help="Write a starter hypothesis under rules/custom")
    init_parser.add_argument("directory", nargs="?", type=Path, default=Path("."))

    args = parser.parse_args(argv)
    try:
        return _dispatch(args)
    except QueryError as exc:
        _print(str(exc))
        return 1
    except FileNotFoundError as exc:
        _print(str(exc))
        return 1


def _dispatch(args) -> int:
    if args.command in {"analyze", "scan"}:
        return _run_analyze(args.target, args.out)
    if args.command == "comment":
        _print(pr_comment(analyze(args.target)))
        return 0
    if args.command == "serve":
        from pathfinder.api import serve

        serve(args.host, args.port, args.report)
        return 0
    if args.command == "install":
        try:
            destination = install(
                args.target,
                platform=args.platform,
                tool=args.tool,
                ref=args.ref,
                force=args.force,
            )
        except InstallError as exc:
            _print(str(exc))
            return 1
        _print(f"Hook written to {destination}")
        _print("Push that repository. The next pull request analyzes its own checkout and attaches the report.")
        return 0
    if args.command == "find-path":
        hypothesis = normalize(
            {
                "name": f"{args.start} to {args.goal}",
                "start": args.start,
                "target": args.goal,
                "through": args.through,
                "conditions": args.condition,
                "must_not_have": args.must_not_have,
                "max_hops": args.max_hops,
            }
        )
        return _run_search(args.target, [hypothesis], args.out)
    if args.command == "simulate":
        return _run_search(args.target, [load_rule_file(args.rule)], args.out)
    if args.command == "hunt":
        result = analyze(args.target)
        if args.name:
            chosen = [hypothesis_by_name(args.name, result.get("root"))]
        else:
            chosen = [item for item in result.get("hypotheses") or [] if item["name"] != "Slight misses"]
            if not chosen:
                chosen = [search(result, item) for item in builtin_hypotheses()]
        _emit(chosen if chosen and "paths" in chosen[0] else [search(result, item) for item in chosen], args.out)
        return 0
    if args.command == "hunts":
        for item in builtin_hypotheses():
            _print(f"{Path(item['source']).stem}: {item['summary'] or item['question']}")
        return 0
    if args.command == "frameworks":
        for item in FRAMEWORKS:
            _print(f"{item['name']}: {item['focus']}")
        return 0
    if args.command == "except":
        try:
            path = record_exception(args.target, rule=args.rule, file=args.file, line=args.line, reason=args.reason, by=args.by)
        except ValueError as exc:
            _print(str(exc))
            return 2
        _print(f"Recorded false positive in {path}")
        return 0
    if args.command == "exceptions":
        entries, error = load_exceptions(args.target)
        if error:
            _print(error)
            return 2
        if not entries:
            _print(f"No false-positive exceptions in {args.target / EXCEPTIONS_FILE}")
            return 0
        for item in entries:
            place = f"{item['file']}:{item['line']}" if item.get("line") else item.get("file") or item.get("fingerprint")
            _print(f"{item['rule']} {place} — {item['reason']}")
        return 0
    if args.command == "ask":
        return _run_search(args.target, [translate(args.question)], args.out)
    if args.command == "query":
        return _run_search(args.target, [parse_graph_query(args.expression)], args.out)
    if args.command == "graph":
        result = apply_history(analyze(args.target), args.out / "history.json")
        paths = write_outputs(result, args.out)
        _print(f"Nodes {len(result['nodes'])}, edges {len(result['edges'])}, composed paths {len(result['paths'])}.")
        _print(f"Graph: {paths['graph']}")
        return 0
    if args.command == "export":
        result = apply_history(analyze(args.target), args.out / "history.json")
        paths = write_outputs(result, args.out)
        if args.fmt == "html":
            _print(str(paths["html"]))
        elif args.fmt == "cypher":
            _print(str(paths["cypher"]))
        else:
            _print(str(paths["json"]))
        return 0
    if args.command == "init":
        destination = args.directory / "rules" / "custom" / "example.yaml"
        if destination.exists():
            _print(f"{destination} already exists")
            return 0
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(_EXAMPLE, encoding="utf-8", newline="\n")
        _print(f"Wrote {destination}")
        _print("Run: python -m pathfinder simulate <repository> rules/custom/example.yaml")
        return 0
    return 1


def _run_analyze(target: Path, out: Path) -> int:
    result = apply_history(analyze(target), out / "history.json")
    paths = write_outputs(result, out)
    _print(result["paths"][0]["narrative"] if result["paths"] else "No attack path composed.")
    reached = [item for item in result.get("hypotheses") or [] if item.get("found")]
    if reached:
        _print(f"Objectives reached: {len(reached)}")
    _print(f"HTML report: {paths['html']}")
    _print(f"Graph: {paths['graph']}")
    _print(f"Threat model: {paths['threat']}")
    return 0


def _run_search(target: Path, hypotheses: list[dict], out: Path | None) -> int:
    result = analyze(target)
    found = [search(result, item) for item in hypotheses]
    _emit(found, out)
    return 0


def _emit(items: list[dict], out: Path | None) -> None:
    text = format_hypotheses(items)
    _print(text or "No hypothesis was run.")
    if out is not None:
        out.mkdir(parents=True, exist_ok=True)
        destination = out / "hypotheses.json"
        destination.write_text(json.dumps(items, indent=2), encoding="utf-8")
        _print(f"Wrote {destination}")


def _print(text: str) -> None:
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", "replace").decode("ascii"))


_EXAMPLE = """name: Payment Fraud
summary: Public payment entry to payment data without an authorization check.
entry:
  - PUBLIC_ENDPOINT
targets:
  - PAYMENT_DB
conditions:
  - no_authz_check
  - user_input_reachable
must_not_have:
  - MFA
  - AUTHORIZATION_CHECK
severity: critical
frameworks:
  - PASTA
  - OWASP API Security Top 10
"""


if __name__ == "__main__":
    raise SystemExit(main())

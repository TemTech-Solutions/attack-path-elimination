from __future__ import annotations

import argparse
import json
from pathlib import Path

from pathfinder.analyze import analyze, apply_history
from pathfinder.install import InstallError, install
from pathfinder.report import pr_comment, write_outputs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compose repository attack paths and write an HTML graph.")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze_parser = sub.add_parser("analyze", help="Analyze a local repository")
    analyze_parser.add_argument("target", type=Path)
    analyze_parser.add_argument("--out", type=Path, default=Path("out"))

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
    install_parser.add_argument("--ref", default="main", help="Git ref of this platform action")
    install_parser.add_argument("--force", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "analyze":
        result = apply_history(analyze(args.target), args.out / "history.json")
        paths = write_outputs(result, args.out)
        _print(result["paths"][0]["narrative"] if result["paths"] else "No attack path composed.")
        _print(f"HTML report: {paths['html']}")
        _print(f"Graph: {paths['graph']}")
        return 0
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
    return 1


def _print(text: str) -> None:
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", "replace").decode("ascii"))


if __name__ == "__main__":
    raise SystemExit(main())

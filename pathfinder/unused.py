"""Unused-code pass for the repository a scan is pointed at.

A removal is recommended only when a private or unexported symbol is defined
once and that name never appears again in the repository. Public symbols that
are defined once are reported and left in place.
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from pathlib import Path

from pathfinder.exceptions import fingerprint, hop_is_excepted, load_exceptions

SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
    "out", "data", ".pathfinder", ".pytest_cache", "vendor", "third_party",
    "site-packages", ".next", "coverage", "bower_components",
}
BINARY = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".woff", ".woff2", ".ttf", ".eot", ".wasm", ".pyc", ".so", ".dll", ".exe",
    ".bin", ".class", ".jar", ".map",
}
LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "cargo.lock", "composer.lock", "gemfile.lock",
}
ENTRY = {
    "main", "init", "setup", "run", "app", "application", "create_app",
    "create_application", "handler", "lambda_handler", "cli", "configure",
    "ready", "setup", "teardown", "setupclass", "teardownclass",
}
WORD = re.compile(r"[A-Za-z_$][\w$]*")
STRINGS = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|`(?:\\.|[^`\\\n])*`')
JS_FUNC = re.compile(r"\b(?:async\s+)?function\*?\s+([A-Za-z_$][\w$]*)\s*\(")
JS_CLASS = re.compile(r"\bclass\s+([A-Za-z_$][\w$]*)\b")
JS_ARROW = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\([^;\n]*\)|[A-Za-z_$][\w$]*)\s*=>"
)
GO_FUNC = re.compile(r"^func\s+(?:\([^)\n]*\)\s*)?([A-Za-z_]\w*)\s*(?:\[|\()")
JAVA_PRIVATE = re.compile(
    r"\bprivate\s+(?:(?:static|final|synchronized|native|strictfp)\s+)*[\w.<>\[\],?\s]+\s([A-Za-z_]\w*)\s*\("
)
CS_PRIVATE = re.compile(
    r"\b(?:private|internal)\s+(?:(?:static|sealed|override|virtual|async|unsafe|new|partial)\s+)*[\w.<>\[\],?\s]+\s([A-Za-z_]\w*)\s*\("
)
PHP_PRIVATE = re.compile(r"\bprivate\s+function\s+([A-Za-z_]\w*)\s*\(")


def find_unused(root: Path) -> dict:
    """Return removal recommendations and the symbols that were deliberately kept."""
    root = Path(root)
    files = _files(root)
    counts: dict[str, int] = defaultdict(int)
    symbols: list[dict] = []
    imports: list[dict] = []
    unparsed = 0
    for rel, text in files:
        for line in text.splitlines():
            for word in WORD.findall(line):
                counts[word] += 1
        suffix = Path(rel).suffix.lower()
        try:
            if suffix == ".py":
                found, imported, failed = _python(rel, text)
                symbols.extend(found)
                imports.extend(imported)
                unparsed += failed
            elif suffix in {".js", ".jsx", ".mjs", ".cjs"}:
                symbols.extend(_script(rel, text, "JavaScript"))
            elif suffix in {".ts", ".tsx"}:
                symbols.extend(_script(rel, text, "TypeScript"))
            elif suffix == ".java":
                symbols.extend(_pattern(rel, text, "Java", JAVA_PRIVATE, "method", True))
            elif suffix == ".go":
                symbols.extend(_go(rel, text))
            elif suffix == ".cs":
                symbols.extend(_pattern(rel, text, "C#", CS_PRIVATE, "method", True))
            elif suffix == ".php":
                symbols.extend(_pattern(rel, text, "PHP", PHP_PRIVATE, "method", True))
        except Exception:
            unparsed += 1
    removals, held, referenced, skipped = _classify(symbols, counts)
    removals.extend(imports)
    removals.sort(key=lambda item: (item["file"], item["line"], item["name"]))
    held.sort(key=lambda item: (item["file"], item["line"], item["name"]))
    omitted = _suppress(root, removals)
    summary = {
        "files": len(files),
        "symbols": len(symbols),
        "removals": len(removals),
        "held": len(held),
        "referenced": referenced,
        "skipped": skipped,
        "unparsed": unparsed,
        "omitted": omitted,
    }
    return {"summary": summary, "removals": removals, "held": held[:40], "held_omitted": max(0, len(held) - 40)}


def _classify(symbols: list[dict], counts: dict[str, int]) -> tuple[list[dict], list[dict], int, int]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for symbol in symbols:
        grouped[symbol["name"]].append(symbol)
    removals: list[dict] = []
    held: list[dict] = []
    referenced = 0
    skipped = 0
    for name, group in grouped.items():
        if _entry_name(name):
            skipped += len(group)
            continue
        if len(group) != 1 or counts.get(name, 0) != 1:
            referenced += len(group)
            continue
        symbol = group[0]
        if symbol["private"]:
            removals.append(_removal(symbol))
        else:
            held.append(_held(symbol))
    return removals, held, referenced, skipped


def _removal(symbol: dict) -> dict:
    name = symbol["name"]
    kind = symbol["kind"]
    language = symbol["language"]
    file = symbol["file"]
    line = symbol["line"]
    evidence = symbol["evidence"]
    if kind == "import":
        what = f"{file} imports {name} and never uses that name."
        effect = f"The import does not change how {file} runs. The rest of the file never reads {name}."
        step = f"Remove {name} from the import at {file}:{line}. Keep any other names on that line that the file still uses."
    elif kind == "class":
        what = f"Private {language} class {name} is defined at {file}:{line} and the name never appears again in this repository."
        effect = f"Nothing in this repository constructs or extends {name}. Deleting it does not change the code that still runs."
        step = f"Delete class {name} at {file}:{line}."
    elif kind == "constant":
        what = f"Private {language} name {name} is assigned at {file}:{line} and never read in this repository."
        effect = f"Nothing in this repository reads {name}. Removing the assignment does not change the code that still runs."
        step = f"Delete the assignment to {name} at {file}:{line}."
    else:
        label = "method" if kind == "method" else "function"
        what = f"Private {language} {label} {name} is defined at {file}:{line} and the name never appears again in this repository."
        effect = f"Nothing in this repository calls {name}. It is not part of an attack path. Removing it deletes code that never runs."
        step = f"Delete {label} {name} at {file}:{line}."
    item = {
        "outcome": "remove",
        "rule": "APP07",
        "name": name,
        "kind": kind,
        "language": language,
        "file": file,
        "line": line,
        "title": f"Unused {kind} {name}",
        "evidence": evidence,
        "what": what,
        "effect": effect,
        "next": step,
        "confidence": "near 100%",
    }
    item["fingerprint"] = fingerprint("APP07", file, evidence)
    return item


def _held(symbol: dict) -> dict:
    name = symbol["name"]
    kind = symbol["kind"]
    file = symbol["file"]
    line = symbol["line"]
    return {
        "outcome": "keep",
        "name": name,
        "kind": kind,
        "language": symbol["language"],
        "file": file,
        "line": line,
        "evidence": symbol["evidence"],
        "what": f"{symbol['language']} {kind} {name} is defined at {file}:{line} and nothing in this repository calls it.",
        "effect": f"{name} is public or exported. A caller outside this repository, or a runtime entry this scan cannot see, may use it.",
        "next": f"Leave {name} in place. Delete it only if you know this repository is the only caller.",
    }


def _suppress(root: Path, removals: list[dict]) -> int:
    try:
        entries, _error = load_exceptions(root)
    except Exception:
        return 0
    if not entries:
        return 0
    kept = [item for item in removals if not hop_is_excepted(item, entries)]
    omitted = len(removals) - len(kept)
    removals[:] = kept
    return omitted


def _python(rel: str, text: str) -> tuple[list[dict], list[dict], int]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return [], [], 1
    lines = text.splitlines()
    symbols: list[dict] = []

    class Walker(ast.NodeVisitor):
        def __init__(self):
            self.stack: list[str] = []

        def visit_ClassDef(self, node: ast.ClassDef):
            if not node.decorator_list:
                _record(symbols, rel, lines, node.name, node.lineno, "class", "Python", _private(node.name))
            self.stack.append("class")
            self.generic_visit(node)
            self.stack.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef):
            self._function(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
            self._function(node)

        def _function(self, node):
            if not node.decorator_list and not _dunder(node.name):
                kind = "method" if "class" in self.stack else "function"
                _record(symbols, rel, lines, node.name, node.lineno, kind, "Python", _private(node.name))
            self.stack.append("func")
            self.generic_visit(node)
            self.stack.pop()

        def visit_Assign(self, node: ast.Assign):
            if not self.stack or self.stack[-1] == "class":
                for target in node.targets:
                    if isinstance(target, ast.Name) and _private(target.id):
                        _record(symbols, rel, lines, target.id, node.lineno, "constant", "Python", True)
            self.generic_visit(node)

    Walker().visit(tree)
    return symbols, _python_imports(rel, text, tree, lines), 0


def _python_imports(rel: str, text: str, tree: ast.AST, lines: list[str]) -> list[dict]:
    if rel.endswith("__init__.py"):
        return []
    loads = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
    found = []
    seen = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or node.module == "__future__":
            continue
        for alias in node.names:
            if alias.name == "*":
                continue
            name = alias.asname or alias.name
            if not name.isidentifier() or name in loads or name in seen:
                continue
            if any(line_no != node.lineno and re.search(rf"\b{re.escape(name)}\b", line) for line_no, line in enumerate(lines, 1)):
                continue
            seen.add(name)
            item = _symbol(rel, lines, name, node.lineno, "import", "Python", True)
            found.append(_removal(item))
    return found


def _script(rel: str, text: str, language: str) -> list[dict]:
    found = []
    for line_no, line in _code_lines(text, "//"):
        exported = bool(re.search(r"\bexport\b", line))
        for pattern, kind in ((JS_FUNC, "function"), (JS_CLASS, "class"), (JS_ARROW, "function")):
            match = pattern.search(line)
            if not match:
                continue
            name = match.group(1)
            if name in {"if", "for", "while", "switch", "catch"}:
                continue
            _record(found, rel, text.splitlines(), name, line_no, kind, language, not exported)
            break
    return found


def _go(rel: str, text: str) -> list[dict]:
    found = []
    lines = text.splitlines()
    for line_no, line in _code_lines(text, "//"):
        match = GO_FUNC.search(line.strip())
        if not match:
            continue
        name = match.group(1)
        _record(found, rel, lines, name, line_no, "function", "Go", name[:1].islower())
    return found


def _pattern(rel: str, text: str, language: str, pattern: re.Pattern, kind: str, private: bool) -> list[dict]:
    found = []
    lines = text.splitlines()
    comment = "//" if language != "PHP" else "//"
    for line_no, line in _code_lines(text, comment):
        paren = line.find("(")
        if paren < 0 or "=" in line[:paren]:
            continue
        match = pattern.search(line[: paren + 1])
        if not match:
            continue
        _record(found, rel, lines, match.group(1), line_no, kind, language, private)
    return found


def _code_lines(text: str, comment: str):
    in_block = False
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw
        if in_block:
            if "*/" in line:
                in_block = False
                line = line.split("*/", 1)[1]
            else:
                continue
        if "/*" in line:
            before, _, after = line.partition("/*")
            if "*/" in after:
                line = before + " " + after.split("*/", 1)[1]
            else:
                in_block = True
                line = before
        stripped = line.strip()
        if stripped.startswith(comment) or stripped.startswith("#") or stripped.startswith("*"):
            continue
        yield line_no, STRINGS.sub('""', line)


def _record(found: list[dict], rel: str, lines: list[str], name: str, line: int, kind: str, language: str, private: bool) -> None:
    if _dunder(name) or name == "_" or len(name) < 2:
        return
    found.append(_symbol(rel, lines, name, line, kind, language, private))


def _symbol(rel: str, lines: list[str], name: str, line: int, kind: str, language: str, private: bool) -> dict:
    evidence = lines[line - 1].strip() if 0 < line <= len(lines) else name
    return {
        "name": name,
        "file": rel,
        "line": line,
        "kind": kind,
        "language": language,
        "private": private,
        "evidence": " ".join(evidence.split())[:180],
    }


def _files(root: Path) -> list[tuple[str, str]]:
    found = []
    if not root.is_dir():
        return found
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name.lower() in LOCKFILES:
            continue
        if path.suffix.lower() in BINARY:
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        found.append((path.relative_to(root).as_posix(), text))
    return found


def _private(name: str) -> bool:
    return name.startswith("_") and not _dunder(name)


def _dunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__")


def _entry_name(name: str) -> bool:
    folded = name.lower()
    if folded in ENTRY:
        return True
    return folded.startswith(("test_", "benchmark_", "example_", "fuzz_")) or name.startswith(("Test", "Benchmark", "Example", "Fuzz"))

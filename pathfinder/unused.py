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
    texts = {rel: text for rel, text in files}
    symbols: list[dict] = []
    imports: list[dict] = []
    module_calls: dict[str, set[str]] = {}
    unparsed = 0
    for rel, text in files:
        suffix = Path(rel).suffix.lower()
        try:
            if suffix == ".py":
                found, imported, failed, called = _python(rel, text)
                symbols.extend(found)
                imports.extend(imported)
                module_calls[rel] = called
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
    dead, held_symbols, referenced, skipped = _reach(symbols, texts, module_calls)
    removals = [_removal(item) for item in dead]
    held = [_held(item) for item in held_symbols]
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
        "depth": "Calls are followed inside each file. Private code is removed only when no public function, import, decorator, or module-level call can reach it, including through other private helpers.",
    }
    return {"summary": summary, "removals": removals, "held": held[:40], "held_omitted": max(0, len(held) - 40)}


def _reach(symbols: list[dict], texts: dict[str, str], module_calls: dict[str, set[str]]):
    """Follow calls inside each file. Private code is dead only when nothing live can reach it."""
    by_file: dict[str, list[dict]] = defaultdict(list)
    for symbol in symbols:
        by_file[symbol["file"]].append(symbol)
    dead: list[dict] = []
    held: list[dict] = []
    referenced = 0
    skipped = 0
    for rel, group in by_file.items():
        lines = texts.get(rel, "").splitlines()
        skipped_here = [item for item in group if _entry_name(item["name"])]
        skipped += len(skipped_here)
        candidates = [item for item in group if item not in skipped_here]
        names: dict[str, list[dict]] = defaultdict(list)
        for item in candidates:
            names[item["name"]].append(item)
        ambiguous = {name for name, items in names.items() if len(items) > 1}
        referenced += sum(len(names[name]) for name in ambiguous)
        chosen = [item for item in candidates if item["name"] not in ambiguous]
        spans = {item["name"]: _span(lines, item) for item in chosen}
        calls = {item["name"]: _callees(item, chosen, lines, spans) for item in chosen}
        roots = {item["name"] for item in chosen if _is_root(item, rel, lines, spans, texts, module_calls.get(rel, set()), chosen)}
        live = set(roots)
        pending = list(roots)
        while pending:
            name = pending.pop()
            for callee in calls.get(name, ()):
                if callee in calls and callee not in live:
                    live.add(callee)
                    pending.append(callee)
        for item in chosen:
            if item["name"] in live:
                reached = (
                    _called_from_elsewhere(item, lines, spans, calls)
                    or item["name"] in module_calls.get(rel, set())
                    or _other_files_mention(item["name"], rel, texts)
                )
                if not item["private"] and not reached:
                    item["why"] = f"Nothing in this repository calls {item['name']}. It stays because it is public or exported and a caller outside this tree may use it."
                    item["window"] = _window(lines, item["line"])
                    held.append(item)
                else:
                    referenced += 1
                continue
            if not item["private"]:
                referenced += 1
                continue
            callers = sorted(name for name, dests in calls.items() if item["name"] in dests)
            if callers:
                item["why"] = (
                    f"No public function, import, decorator, or module-level call reaches {item['name']}. "
                    f"The only callers are other unused private code: {', '.join(callers)}."
                )
            else:
                item["why"] = f"No function, import, decorator, or module-level call in this repository reaches {item['name']}."
            item["window"] = _window(lines, item["line"])
            item["depth"] = "call graph"
            dead.append(item)
    return dead, held, referenced, skipped


def _removal(symbol: dict) -> dict:
    name = symbol["name"]
    kind = symbol["kind"]
    language = symbol["language"]
    file = symbol["file"]
    line = symbol["line"]
    evidence = symbol["evidence"]
    why = symbol.get("why") or "The name is never reached from code that still runs."
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
        clustered = "unused private code" in why
        snippet = " ".join(str(evidence or "").split())
        quoted = f" The line is `{snippet}`." if snippet else ""
        what = (
            f"Private {language} {label} {name} at {file}:{line} is only reached from other unused private code.{quoted}"
            if clustered
            else f"Private {language} {label} {name} at {file}:{line} is not reached by any code that still runs.{quoted}"
        )
        effect = (
            f"No live code calls {name}. Removing it, together with the unused private code that calls it, deletes code that never runs. This is not an attack path, and it cannot be a foothold."
            if clustered
            else f"Nothing that still runs calls {name}. This is not an attack path, and it cannot be a foothold, because no running code can reach it. Removing it deletes code that never runs."
        )
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
        "why": why,
        "window": symbol.get("window") or evidence,
        "depth": symbol.get("depth") or "call graph",
        "confidence": "near 100%",
        "priority": 1,
        "database": _database("CWE-561"),
        "architecture": (
            f"Removing {name} does not change the architecture of the code that still runs. "
            "Nothing live calls it. CWE-1164 describes unreachable code as having no impact on intended functionality when it is removed."
        ),
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
        "architecture": (
            f"Removing {name} can change the current architecture. "
            "It is public or exported, so a caller outside this repository may depend on it. This scan leaves it in place."
        ),
    }


def _database(key: str) -> str:
    from pathfinder.catalog import RECORDS, present

    return present(RECORDS.get(key) or {})


def add_unused_components(unused: dict, nodes: list[dict], observations: list[dict], root: Path) -> dict:
    """Add graph components that nothing calls, on the same list as unused code."""
    flagged = {item.get("node_id") for item in observations or [] if item.get("node_id")}
    removals = unused.setdefault("removals", [])
    held = unused.setdefault("held", [])
    known = {(item.get("file"), item.get("name")) for item in list(removals) + list(held)}
    added = 0
    for node in nodes or []:
        kind = node.get("kind")
        if kind not in {"function", "workflow", "workload"}:
            continue
        file = str(node.get("file") or "")
        if kind == "function" and Path(file).suffix.lower() in {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".go", ".cs", ".php"}:
            continue
        if node.get("incoming") or node.get("attack_paths") or node.get("id") in flagged:
            continue
        name = str(node.get("name") or "")
        if not name or (file, name) in known or _entry_name(name):
            continue
        known.add((file, name))
        if kind == "function" and not _private(name):
            held.append(_held_component(node))
            continue
        removals.append(_unused_component(node))
        added += 1
    removals.sort(key=lambda item: (item.get("priority", 1), item.get("file") or "", item.get("line") or 0, item.get("name") or ""))
    _suppress(Path(root), removals)
    summary = unused.setdefault("summary", {})
    summary["removals"] = len(removals)
    summary["components"] = added
    summary["held"] = max(int(summary.get("held") or 0), len(held))
    if len(held) > 40:
        unused["held_omitted"] = int(unused.get("held_omitted") or 0) + (len(held) - 40)
        unused["held"] = held[:40]
    else:
        unused["held"] = held
    return unused


def _unused_component(node: dict) -> dict:
    name = str(node.get("name") or "component")
    kind = str(node.get("kind") or "component")
    file = str(node.get("file") or "")
    line = node.get("line") or 1
    place = f"{file}:{line}" if file else "this repository"
    surface = kind in {"workflow", "workload"}
    evidence = f"{kind} {name}"
    if surface:
        what = f"Unused {kind} {name} at {place} is in the analyzed graph, and nothing in that graph invokes it."
        effect = f"No trigger or service routes to {name}. It is not on an attack path."
        architecture = (
            f"Removing {name} does not change the architecture of the paths that still have a caller. "
            "Nothing in this graph depends on it."
        )
        database = _database("API9")
        priority = 0
    else:
        what = f"Unused {kind} {name} at {place} has no caller in the analyzed graph."
        effect = f"No component calls {name}. This is not an attack path, and it cannot be a foothold."
        architecture = (
            f"Removing {name} does not change the architecture of the code that still runs. "
            "CWE-1164 describes unreachable code as having no impact on intended functionality when it is removed."
        )
        database = _database("CWE-561")
        priority = 1
    item = {
        "outcome": "remove",
        "rule": "APP07",
        "name": name,
        "kind": kind,
        "language": node.get("language") or "",
        "file": file,
        "line": line,
        "title": f"Unused {kind} {name}",
        "evidence": evidence,
        "what": what,
        "effect": effect,
        "next": f"Delete {kind} {name} at {place}.",
        "why": f"The analyzed graph has no incoming call to {name}.",
        "window": evidence,
        "depth": "component graph",
        "confidence": "graph",
        "priority": priority,
        "database": database,
        "architecture": architecture,
    }
    item["fingerprint"] = fingerprint("APP07", file, evidence)
    return item


def _held_component(node: dict) -> dict:
    name = str(node.get("name") or "component")
    kind = str(node.get("kind") or "function")
    file = str(node.get("file") or "")
    line = node.get("line") or 1
    return {
        "outcome": "keep",
        "name": name,
        "kind": kind,
        "language": node.get("language") or "",
        "file": file,
        "line": line,
        "evidence": f"{kind} {name}",
        "what": f"{kind} {name} at {file}:{line} has no caller in this graph, and it is public or exported.",
        "effect": f"A caller outside this repository may use {name}.",
        "next": f"Leave {name} in place.",
        "why": f"Nothing in this repository calls {name}, but the name is not private.",
        "architecture": (
            f"Removing {name} can change the current architecture. "
            "A caller outside this repository may depend on this public component."
        ),
        "confidence": "graph",
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


def _python(rel: str, text: str) -> tuple[list[dict], list[dict], int, set[str]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return [], [], 1, set()
    lines = text.splitlines()
    symbols: list[dict] = []
    module_calls: set[str] = set()

    class Walker(ast.NodeVisitor):
        def __init__(self):
            self.funcs = 0
            self.classes = 0

        def visit_ClassDef(self, node: ast.ClassDef):
            if not node.decorator_list:
                _record(symbols, rel, lines, node.name, node.lineno, "class", "Python", _private(node.name), _uses_in(node.body))
            self.classes += 1
            self.generic_visit(node)
            self.classes -= 1

        def visit_FunctionDef(self, node: ast.FunctionDef):
            self._function(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
            self._function(node)

        def _function(self, node):
            if node.decorator_list:
                module_calls.update(_uses_in(node.body))
            elif not _dunder(node.name):
                kind = "method" if self.classes else "function"
                _record(symbols, rel, lines, node.name, node.lineno, kind, "Python", _private(node.name), _uses_in(node.body))
            self.funcs += 1
            for stmt in node.body:
                self.visit(stmt)
            self.funcs -= 1

        def visit_Call(self, node: ast.Call):
            self.generic_visit(node)

        def visit_Name(self, node: ast.Name):
            if self.funcs == 0 and isinstance(node.ctx, ast.Load):
                module_calls.add(node.id)

        def visit_Attribute(self, node: ast.Attribute):
            if self.funcs == 0 and isinstance(node.ctx, ast.Load):
                module_calls.add(node.attr)
            self.generic_visit(node)

        def visit_Assign(self, node: ast.Assign):
            if self.funcs == 0:
                for target in node.targets:
                    if isinstance(target, ast.Name) and _private(target.id):
                        _record(symbols, rel, lines, target.id, node.lineno, "constant", "Python", True, [])
            self.generic_visit(node)

    Walker().visit(tree)
    return symbols, _python_imports(rel, text, tree, lines), 0, module_calls


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


def _record(found: list[dict], rel: str, lines: list[str], name: str, line: int, kind: str, language: str, private: bool, calls: list[str] | None = None) -> None:
    if _dunder(name) or name == "_" or len(name) < 2:
        return
    found.append(_symbol(rel, lines, name, line, kind, language, private, calls or []))


def _symbol(rel: str, lines: list[str], name: str, line: int, kind: str, language: str, private: bool, calls: list[str] | None = None) -> dict:
    evidence = lines[line - 1].strip() if 0 < line <= len(lines) else name
    return {
        "name": name,
        "file": rel,
        "line": line,
        "kind": kind,
        "language": language,
        "private": private,
        "calls": list(calls or []),
        "evidence": " ".join(evidence.split())[:180],
    }


def _uses_in(statements) -> list[str]:
    found: list[str] = []

    class Grab(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef):
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
            return

        def visit_ClassDef(self, node: ast.ClassDef):
            return

        def visit_Name(self, node: ast.Name):
            if isinstance(node.ctx, ast.Load):
                found.append(node.id)

        def visit_Attribute(self, node: ast.Attribute):
            if isinstance(node.ctx, ast.Load):
                found.append(node.attr)
            self.generic_visit(node)

    for statement in statements:
        Grab().visit(statement)
    return found


def _span(lines: list[str], symbol: dict) -> tuple[int, int]:
    if symbol["language"] == "Python":
        return symbol["line"], symbol["line"]
    start = symbol["line"]
    depth = 0
    seen = False
    for index in range(start - 1, len(lines)):
        line = STRINGS.sub('""', lines[index])
        for char in line:
            if char == "{":
                depth += 1
                seen = True
            elif char == "}" and seen:
                depth -= 1
                if depth <= 0:
                    return start, index + 1
    return start, start if not seen else len(lines)


def _callees(symbol: dict, group: list[dict], lines: list[str], spans: dict[str, tuple[int, int]]) -> set[str]:
    if symbol["language"] == "Python":
        return set(symbol.get("calls") or [])
    start, end = spans[symbol["name"]]
    body = "\n".join(lines[start - 1 : end])
    return {
        other["name"]
        for other in group
        if other["name"] != symbol["name"] and re.search(rf"\b{re.escape(other['name'])}\b", body)
    }


def _is_root(symbol: dict, rel: str, lines: list[str], spans: dict[str, tuple[int, int]], texts: dict[str, str], called_at_module: set[str], group: list[dict]) -> bool:
    name = symbol["name"]
    if not symbol["private"]:
        return True
    if name in called_at_module:
        return True
    if _other_files_mention(name, rel, texts):
        return True
    if symbol["language"] == "Python":
        return False
    start, end = spans[name]
    private_spans = [spans[item["name"]] for item in group if item["private"] and item["name"] in spans]
    for line_no, line in enumerate(lines, 1):
        if start <= line_no <= end or not re.search(rf"\b{re.escape(name)}\b", line):
            continue
        if any(span_start <= line_no <= span_end for span_start, span_end in private_spans):
            continue
        return True
    return False


def _called_from_elsewhere(symbol: dict, lines: list[str], spans: dict[str, tuple[int, int]], calls: dict[str, set[str]]) -> bool:
    name = symbol["name"]
    if any(name in dests and caller != name for caller, dests in calls.items()):
        return True
    if symbol["language"] == "Python":
        return False
    start, end = spans.get(name, (symbol["line"], symbol["line"]))
    for line_no, line in enumerate(lines, 1):
        if start <= line_no <= end:
            continue
        if re.search(rf"\b{re.escape(name)}\b", line):
            return True
    return False


def _other_files_mention(name: str, rel: str, texts: dict[str, str]) -> bool:
    pattern = re.compile(rf"\b{re.escape(name)}\b")
    return any(other != rel and pattern.search(text) for other, text in texts.items())


def _window(lines: list[str], line: int, radius: int = 3) -> str:
    if not lines:
        return ""
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    return "\n".join(f"{number}: {lines[number - 1]}" for number in range(start, end + 1))


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

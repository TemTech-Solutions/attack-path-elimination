"""Structural extraction for every source language.

Known languages keep their own parsers. Every other program is read here, and
every program — known or not — gets a second pass for the smaller signals
those parsers do not name. The output is the same graph: a component, the
line that shows the edge, and the deletion or constraint.
"""

from __future__ import annotations

import re
from pathlib import Path

from pathfinder.baseline import rule_recommendation
from pathfinder.model import RepoModel

MAX_ROUTES = 40
MAX_FUNCTIONS = 80
MAX_SIGNALS = 200

SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".tgz", ".bz2", ".7z", ".wasm", ".woff", ".woff2", ".ttf", ".eot", ".mp4",
    ".mp3", ".wav", ".sqlite", ".db", ".class", ".jar", ".so", ".dll", ".exe",
    ".bin", ".map", ".svg", ".sum", ".pyc", ".pyo",
}
SKIP_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock",
    "composer.lock", "gemfile.lock", "poetry.lock",
}
CONFIG_EXT = {".yml", ".yaml", ".json", ".env", ".ini", ".toml", ".properties", ".xml", ".conf", ".cfg"}
EXT = {
    ".py": "python", ".pyw": "python", ".ipynb": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".vue": "vue", ".svelte": "svelte",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala", ".groovy": "groovy",
    ".go": "go", ".rs": "rust", ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hpp": "cpp", ".hh": "cpp", ".m": "objective-c", ".mm": "objective-c",
    ".cs": "csharp", ".fs": "fsharp", ".vb": "vb", ".php": "php", ".phtml": "php",
    ".rb": "ruby", ".rake": "ruby", ".erb": "ruby", ".ex": "elixir", ".exs": "elixir",
    ".erl": "erlang", ".hrl": "erlang", ".clj": "clojure", ".cljs": "clojure",
    ".hs": "haskell", ".ml": "ocaml", ".mli": "ocaml", ".lua": "lua", ".pl": "perl", ".pm": "perl",
    ".r": "r", ".R": "r", ".jl": "julia", ".dart": "dart", ".swift": "swift",
    ".zig": "zig", ".nim": "nim", ".cr": "crystal", ".d": "d", ".pas": "pascal",
    ".f": "fortran", ".f90": "fortran", ".cob": "cobol", ".cbl": "cobol",
    ".sol": "solidity", ".move": "move", ".vy": "vyper",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ps1": "powershell", ".psm1": "powershell",
    ".bat": "batch", ".cmd": "batch", ".sql": "sql", ".tf": "terraform", ".hcl": "hcl",
    ".html": "html", ".htm": "html", ".ejs": "javascript", ".jinja": "python", ".j2": "python",
}

SENSITIVE = re.compile(
    r"(admin|debug|console|actuator|internal|payment|refund|upload|exec|shell|config|secret|wallet|coupon)",
    re.I,
)
AUTH = re.compile(
    r"\b(authorize|authenticated|login_required|jwt_required|requires_auth|PreAuthorize|RolesAllowed|Secured|middleware)\b",
    re.I,
)
ANON = re.compile(r"AllowAnonymous|AllowAny|csrf_exempt|permitAll|auth\s*[:=]\s*false|\[Authorize\(Anonymous\)\]", re.I)
EXEC = re.compile(
    r"(?:"
    r"\b(?:eval|exec|system|popen|shell_exec|passthru|unserialize)\s*\("
    r"|os\.system\s*\("
    r"|subprocess\.(?:call|run|Popen|check_output|getoutput)\s*\("
    r"|shell\s*=\s*True"
    r"|pickle\.loads\s*\("
    r"|yaml\.load\s*\("
    r"|Runtime\.getRuntime\s*\("
    r"|Process\.Start\s*\("
    r"|exec\.Command\s*\("
    r"|syscall\.Exec\s*\("
    r"|child_process\.(?:exec|spawn)"
    r"|BinaryFormatter"
    r"|ObjectInputStream"
    r"|\breadObject\s*\("
    r"|Marshal\.load\s*\("
    r")",
    re.I,
)
SQL_BUILD = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE)\b.{0,160}(\+|%s|%\{|\$\{|\.format\s*\(|f[\"']|\$[A-Za-z_])",
    re.I,
)
HTTP_VAR = re.compile(
    r"\b(?:fetch|axios|requests\.(?:get|post|put|delete)|http\.get|got|openStream|WebClient|RestTemplate|curl_exec|httpx\.(?:get|post)|URL)\s*\(\s*(?:request|req|params|input|query|body|args|url|uri|callback|target|user|host|dest)\b",
    re.I,
)
SECRET_ASSIGN = re.compile(
    r"""\b(?P<name>[A-Za-z_][A-Za-z0-9_]*(?:secret|password|passwd|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|credential|_key)s?)\b\s*[:=]\s*(?P<value>['\"][^'\"]+['\"]|\S+)""",
    re.I,
)
PLACEHOLDER = re.compile(
    r"placeholder|changeme|example|your[-_]?token|todo|dummy|fake|not[-_]?a[-_]?secret|xxx+|redacted|sample",
    re.I,
)
SCHEMA_KEYS = {"primary_key", "foreign_key", "sort_key", "partition_key"}
FUNC = re.compile(
    r"""(?m)^[ \t]*(?:(?:pub|public|private|protected|internal|static|async|export|virtual|override|def|fn|fun|func|function|sub|proc|procedure)\s+)*"""
    r"""(?:function|func|fn|fun|def|sub|proc|procedure)\s+(?P<name>[A-Za-z_][\w]*)"""
)
METHOD = re.compile(
    r"""(?m)^[ \t]*(?:public|private|protected|internal)\s+(?:static\s+)?(?:[\w.<>,\[\]]+\s+)(?P<name>[A-Za-z_]\w*)\s*\("""
)
ROUTES = (
    re.compile(r"""@(?:Get|Post|Put|Delete|Patch|Request)Mapping\(\s*(?:value\s*=\s*)?['\"](?P<path>/[^'\"]+)['\"]""", re.I),
    re.compile(r"""\[Http(?P<verb>Get|Post|Put|Delete|Patch)\(\s*['\"](?P<path>/[^'\"]*)['\"]""", re.I),
    re.compile(r"""#\[(?P<verb>get|post|put|delete|patch)\(\s*['\"](?P<path>/[^'\"]+)['\"]\s*\)\]""", re.I),
    re.compile(r"""\b(?P<verb>get|post|put|patch|delete)\s*[\(\s]\s*['\"](?P<path>/[^'\"]+)['\"]""", re.I),
    re.compile(r"""\b(?P<verb>GET|POST|PUT|DELETE|PATCH)\s+(?P<path>/[A-Za-z0-9_./{}:-]+)\b"""),
)
SKIP_NAMES_FUNC = {"if", "for", "while", "switch", "catch", "return", "class", "struct", "enum", "new"}

# Smaller signals. Each one is a structural fact and a deletion or constraint.
SIGNALS = (
    ("review", "APP08", "internal", "none", "internal", "misconfiguration",
     re.compile(r"verify\s*=\s*False|InsecureSkipVerify|NODE_TLS_REJECT_UNAUTHORIZED|rejectUnauthorized\s*:\s*false|CERT_NONE|TrustAll", re.I),
     "Certificate check is disabled",
     "Remove the disabled certificate check. Keep verification on for every outbound call."),
    ("review", "APP10", "public", "none", "internal", "misconfiguration",
     re.compile(r"Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]?\*|origin\s*:\s*['\"]\*['\"]|AllowAnyOrigin", re.I),
     "Wildcard cross-origin policy",
     "Remove the wildcard origin. Allow only the origins this service actually serves."),
    ("review", "APP06", "internal", "none", "internal", "misconfiguration",
     re.compile(r"\b0\.0\.0\.0\b"),
     "Service listens on every interface",
     "Remove the bind on every interface. Listen on the address this service is supposed to use."),
    ("review", "APP06", "internal", "admin", "internal", "misconfiguration",
     re.compile(r"\b0o777\b|\bchmod\s+777\b|mode\s*[:=]\s*0?777\b"),
     "World-writable file mode",
     "Remove world-writable permissions. Keep the mode limited to the account that runs the service."),
    ("review", "APP03", "internal", "credential", "credential", "misconfiguration",
     re.compile(r"\b(md5|sha1)\b", re.I),
     "Weak hash used beside a credential",
     "Remove MD5 and SHA-1 from password or token handling. Use a password hashing function."),
    ("review", "APP01", "public", "none", "internal", "misconfiguration",
     re.compile(r"\bDEBUG\s*=\s*True\b|app\.debug\s*=\s*True|display_errors\s*=\s*On", re.I),
     "Debug switch left on",
     "Remove the debug switch from the production configuration."),
    ("unauthenticated", "APP10", "public", "admin", "internal", "missing_auth",
     ANON,
     "Anonymous authorization exception",
     "Remove the anonymous authorization exception from any route that touches privileged data."),
    ("review", "APP08", "public", "ssrf", "internal", "user_controlled",
     re.compile(r"\bredirect\s*\(\s*(request|req|params|input|query)\b", re.I),
     "Redirect target is taken from the request",
     "Remove the redirect target taken from the request. Allow only a fixed set of destinations."),
    ("review", "APP09", "public", "none", "internal", "user_controlled",
     re.compile(r"open\(\s*[^)]*\+|os\.path\.join\(\s*[^)]*request|filepath\.Join\(|Path\(\s*[^)]*request", re.I),
     "File path is built from request data",
     "Remove the file path built from request data. Open a fixed directory entry."),
    ("review", "APP03", "internal", "credential", "credential", "misconfiguration",
     re.compile(r"Math\.random\s*\(|\brand\s*\("),
     "Non-cryptographic randomness beside a token",
     "Remove non-cryptographic randomness from token and session creation."),
    ("review", "APP02", "public", "none", "internal", "user_controlled",
     re.compile(r"innerHTML|dangerouslySetInnerHTML|document\.write\s*\(", re.I),
     "Caller-controlled markup is written into the page",
     "Remove the write of caller-controlled markup. Put the data in text, not in HTML."),
    ("rce", "APP05", "public", "rce", "production", "user_controlled", EXEC,
     "Dynamic execution primitive",
     None),
    ("sqli", "APP09", "public", "data", "sensitive", "user_controlled", SQL_BUILD,
     "Query is built from a string",
     None),
    ("ssrf", "APP08", "public", "ssrf", "internal", "user_controlled", HTTP_VAR,
     "Outbound request is built from a variable",
     None),
)


def language_of(path: Path, text: str) -> str | None:
    name = path.name.lower()
    if name in SKIP_NAMES or path.suffix.lower() in SKIP_EXT:
        return None
    if "\0" in text[:8000]:
        return None
    if name.startswith(".env") or path.suffix.lower() in CONFIG_EXT or name.endswith(".env"):
        return "config"
    suffix = path.suffix.lower()
    if suffix in EXT:
        return EXT[suffix]
    shebang = re.match(r"^#!.*\b(python|python3|ruby|perl|node|nodejs|php|bash|sh|lua)\b", text, re.I)
    if shebang:
        token = shebang.group(1).lower()
        return {"python3": "python", "node": "javascript", "nodejs": "javascript", "sh": "shell", "bash": "shell"}.get(token, token)
    sniffed = _sniff(text)
    if sniffed:
        return sniffed
    if _code_score(text) >= 2:
        return "source"
    return None


def analyze_unclaimed(model: RepoModel, rel: str, text: str) -> None:
    language = language_of(Path(rel), text)
    if not language or language == "config":
        return
    for start, verb, path, evidence in _route_hits(text):
        line = text[:start].count("\n") + 1
        window = text[start : start + 1400]
        before = text[max(0, start - 240) : start]
        handler_name = _handler_name(window, verb, path)
        auth = bool(AUTH.search(before + window[:280])) and not ANON.search(before + window[:280])
        handler = model.node(
            "function",
            handler_name,
            file=rel,
            line=line,
            lane="service",
            language=language,
            receives=f"{verb} {path}",
        )
        endpoint = model.node(
            "endpoint",
            f"{verb} {path}",
            file=rel,
            line=line,
            lane="entry",
            language=language,
            receives=f"{verb} {path}",
            properties={"method": verb, "path": path, "auth": auth, "framework": language, "handler": handler_name},
        )
        model.edge(endpoint, handler, "ROUTES_TO", file=rel, line=line, evidence=evidence)
        if not auth:
            sensitive = bool(SENSITIVE.search(path) or SENSITIVE.search(handler_name))
            _observe(
                model,
                theme="unauthenticated",
                rule="APP10" if sensitive else "APP01",
                title="Unauthenticated route" if sensitive else "Route without an auth check",
                node_id=handler,
                file=rel,
                line=line,
                evidence=f"{verb} {path}",
                exposure="public",
                privilege="admin" if sensitive else "none",
                asset="financial" if sensitive else "internal",
                exploitability="missing_auth",
            )
        _sinks(model, rel, line, language, handler, window)
    for name, line in _functions(text):
        node_id = model.node("function", name, file=rel, line=line, lane="service", language=language)
        _remember(model, name, rel, line, node_id)


def deepen(model: RepoModel, root: Path) -> None:
    """Second pass over every program and config file. Skips a line the first pass already recorded."""
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "out", "data", ".pathfinder", ".pytest_cache"} for part in path.parts):
            continue
        if path.stat().st_size > 1_000_000:
            continue
        if path.name.lower() in {"pathfinder-exceptions.yml", "pathfinder-exceptions.yaml"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        language = language_of(path, text)
        if not language:
            continue
        rel = _rel(root, path)
        _secrets(model, rel, text, language)
        if language == "config":
            _signals(model, rel, text, language, config_only=True)
        else:
            _signals(model, rel, text, language, config_only=False)


def _sinks(model: RepoModel, rel: str, line: int, language: str, handler: str, window: str) -> None:
    exec_line = _first_code(window, EXEC)
    if exec_line and not _near(model, rel, line, "rce"):
        _observe(model, theme="rce", rule="APP05", title="Dynamic execution primitive", node_id=handler, file=rel, line=line, evidence=exec_line, exposure="public", privilege="rce", asset="production", exploitability="user_controlled")
    sql_line = _first_code(window, SQL_BUILD)
    if sql_line and not _near(model, rel, line, "sqli"):
        _observe(model, theme="sqli", rule="APP09", title="Query is built from a string", node_id=handler, file=rel, line=line, evidence=sql_line, exposure="public", privilege="data", asset="sensitive", exploitability="user_controlled")
        table = re.search(r"\bFROM\s+([A-Za-z_][\w]*)", window, re.I)
        store = model.node(
            "datastore",
            table.group(1) if table else "SQL database",
            lane="data",
            unique=True,
            file=rel,
            language=language,
            properties={"table": table.group(1) if table else "", "sensitive": True},
        )
        model.edge(handler, store, "READS", file=rel, line=line, evidence=sql_line)
    http_line = _first_code(window, HTTP_VAR)
    if http_line and not _near(model, rel, line, "ssrf"):
        _observe(model, theme="ssrf", rule="APP08", title="Outbound request is built from a variable", node_id=handler, file=rel, line=line, evidence=http_line, exposure="public", privilege="ssrf", asset="internal", exploitability="user_controlled")


def _signals(model: RepoModel, rel: str, text: str, language: str, *, config_only: bool) -> None:
    lines = text.splitlines()
    emitted = 0
    for index, raw in enumerate(lines, start=1):
        if emitted >= MAX_SIGNALS:
            return
        if not _code_line(raw):
            continue
        previous = lines[index - 2] if index > 1 else ""
        blob = raw if not previous else previous + " " + raw
        for theme, rule, exposure, privilege, asset, exploit, pattern, title, recommendation in SIGNALS:
            if config_only and theme in {"rce", "sqli", "ssrf"}:
                continue
            if title.startswith("Service listens") and not re.search(r"bind|listen|host|addr|interface|INADDR", raw, re.I):
                continue
            if title.startswith("Weak hash") and not re.search(r"password|secret|token|session", raw, re.I):
                continue
            if title.startswith("Non-cryptographic") and not re.search(r"password|secret|token|session", raw, re.I):
                continue
            matched = pattern.search(raw) or (theme == "sqli" and pattern.search(blob))
            if not matched:
                continue
            if _near(model, rel, index, theme, window=8):
                continue
            anchor = _anchor(model, rel, index, language, title)
            _observe(
                model,
                theme=theme,
                rule=rule,
                title=title,
                node_id=anchor,
                file=rel,
                line=index,
                evidence=raw.strip()[:180],
                exposure=exposure,
                privilege=privilege,
                asset=asset,
                exploitability=exploit,
                recommendation=recommendation,
            )
            emitted += 1
            break


def _secrets(model: RepoModel, rel: str, text: str, language: str) -> None:
    for index, raw in enumerate(text.splitlines(), start=1):
        if not _code_line(raw):
            continue
        match = SECRET_ASSIGN.search(raw)
        if not match or _near(model, rel, index, "credential", window=6):
            continue
        value = match.group("value")
        if re.search(r"environ|process\.env|getenv|ENV\[|None|null|nil|undefined|secret\(|config\(", value, re.I):
            continue
        if value.strip("\"'") == "":
            continue
        name = match.group("name")
        if name.lower() in SCHEMA_KEYS or not _secret_value_ok(name, value):
            continue
        secret = model.node("secret", name, lane="credential", unique=True, file=rel, line=index, language=language)
        anchor = _anchor(model, rel, index, language, name)
        model.edge(anchor, secret, "USES_SECRET", file=rel, line=index, evidence=f"{name} is assigned in source")
        _observe(
            model,
            theme="credential",
            rule="APP03",
            title="Credential is assigned in source",
            node_id=secret,
            file=rel,
            line=index,
            evidence=f"{name} is assigned in source",
            exposure="internal",
            privilege="credential",
            asset="credential",
            exploitability="misconfiguration",
            recommendation="Remove the literal credential from source. Read it from the environment or a secret store at runtime.",
        )
        _remember(model, name, rel, index, secret)


def _secret_value_ok(name: str, value: str) -> bool:
    inner = value.strip("\"'").strip()
    if PLACEHOLDER.search(inner) or len(inner) < 8 or re.fullmatch(r"[A-Za-z]+", inner):
        return False
    weak_name = name.lower().endswith("_key") and not re.search(r"secret|password|token|credential|api|private|access", name, re.I)
    if weak_name and not re.search(r"\d", inner):
        return False
    return True


def _observe(model, **observation) -> None:
    if observation.get("recommendation") is None:
        observation["recommendation"] = rule_recommendation(observation["rule"])
    observation.setdefault("stage", "review")
    observation.setdefault("identity", False)
    model.observe(**observation)


def _route_hits(text: str) -> list[tuple[int, str, str, str]]:
    found = []
    seen = set()
    for pattern in ROUTES:
        for match in pattern.finditer(text):
            path = match.group("path")
            if not path.startswith("/") or path.startswith("//"):
                continue
            verb = (match.groupdict().get("verb") or "GET").upper()
            if verb == "REQUEST":
                verb = "GET"
            key = (verb, path, text[: match.start()].count("\n"))
            if key in seen:
                continue
            seen.add(key)
            found.append((match.start(), verb, path, " ".join(match.group(0).split())[:160]))
            if len(found) >= MAX_ROUTES:
                return found
    return found


def _functions(text: str) -> list[tuple[str, int]]:
    found = []
    seen = set()
    for pattern in (FUNC, METHOD):
        for match in pattern.finditer(text):
            name = match.group("name")
            if name.lower() in SKIP_NAMES_FUNC or name in seen:
                continue
            seen.add(name)
            found.append((name, text[: match.start()].count("\n") + 1))
            if len(found) >= MAX_FUNCTIONS:
                return found
    return found


def _handler_name(window: str, verb: str, path: str) -> str:
    match = re.search(r"\b(?:def|fn|fun|func|function|sub)\s+([A-Za-z_]\w*)", window[:220])
    if match and match.group(1).lower() not in SKIP_NAMES_FUNC:
        return match.group(1)
    return f"{verb} {path}"


def _anchor(model: RepoModel, rel: str, line: int, language: str, name: str) -> str:
    best = None
    for node in model.nodes.values():
        if node.get("file") != rel or node.get("kind") not in {"function", "endpoint", "workload"}:
            continue
        node_line = node.get("line") or 0
        if node_line <= line and (best is None or node_line >= (best.get("line") or 0)):
            best = node
    if best:
        return best["id"]
    return model.node("function", name[:80], file=rel, line=line, lane="service", language=language)


def _remember(model: RepoModel, text: str, rel: str, line: int, node_id: str) -> None:
    samples = getattr(model, "samples", None)
    if samples is None:
        samples = []
        model.samples = samples
    samples.append({"text": text, "file": rel, "line": line, "node_id": node_id})


def _near(model: RepoModel, file: str, line: int, theme: str, window: int = 30) -> bool:
    for item in model.observations:
        if item.get("file") != file or item.get("theme") != theme:
            continue
        other = item.get("line") or 0
        if abs(other - line) <= window:
            return True
    return False


def _first_code(window: str, pattern: re.Pattern) -> str:
    for match in pattern.finditer(window):
        start = window.rfind("\n", 0, match.start()) + 1
        end = window.find("\n", match.start())
        line = window[start:] if end < 0 else window[start:end]
        if _code_line(line):
            return line.strip()[:180]
    return ""


def _code_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    return not stripped.startswith(("#", "//", "--", "/*", "*"))


def _code_score(text: str) -> int:
    hits = re.findall(r"\b(def|function|func|fn|class|import|package|module|sub|proc|fun)\b", text[:4000])
    return len(hits)


def _sniff(text: str) -> str | None:
    sample = text[:4000]
    checks = (
        ("php", r"<\?php"),
        ("rust", r"\bfn\s+\w+"),
        ("kotlin", r"\bfun\s+\w+"),
        ("swift", r"\bfunc\s+\w+"),
        ("go", r"\bfunc\s+\w+"),
        ("ruby", r"\bdef\s+\w+"),
        ("python", r"(?m)^\s*def\s+\w+"),
        ("elixir", r"\bdefmodule\b"),
        ("haskell", r"(?m)^\s*module\s+\w+"),
        ("lua", r"\bfunction\s+\w+"),
        ("perl", r"\bsub\s+\w+"),
        ("csharp", r"\bnamespace\s+\w+"),
        ("java", r"\bpublic\s+class\b"),
        ("c", r"#include\s*<"),
        ("javascript", r"\bfunction\s+\w+"),
    )
    for name, pattern in checks:
        if re.search(pattern, sample):
            return name
    return None


def _rel(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()

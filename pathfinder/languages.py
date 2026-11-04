"""Structural extraction.

Python uses the stdlib AST. Other languages use grammar-shaped patterns for
routes, calls, and sinks. That is enough to connect components; it is not a
substitute for a full compiler frontend.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from pathfinder.baseline import rule_recommendation
from pathfinder.model import RepoModel

BUILTIN_CALLS = {
    "get", "post", "put", "delete", "str", "dict", "list", "print", "int", "bool",
    "len", "open", "set", "super", "isinstance", "getattr", "setattr", "hasattr",
    "enumerate", "range", "map", "filter", "zip", "type", "min", "max", "sum",
    "any", "all", "sorted", "reversed", "format", "repr", "hash", "iter", "next",
    "staticmethod", "classmethod", "property", "tuple", "float", "bytes", "object",
}

AUTH_DECORATORS = re.compile(
    r"(login_required|jwt_required|auth_required|requires_auth|require_auth|authorized|permission_required|roles_required)",
    re.I,
)
SENSITIVE_PATH = re.compile(
    r"(admin|debug|console|actuator|internal|payment|refund|upload|exec|shell|config|secret|wallet|coupon)",
    re.I,
)
PRIVILEGED_CALL = re.compile(
    r"(approve|admin|refund|credit|grant|delete_user|set_role|wallet|payout|privilege)",
    re.I,
)
METADATA_HOSTS = (
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.azure.com",
    "computemetadata",
)
MONEY_NAME = re.compile(r"(credit|coupon|wallet|refund|bonus|payout|redeem)", re.I)
MONEY_PARAMS = {"amount", "value", "qty", "quantity", "price", "sum"}
SQL_WORDS = ("SELECT", "INSERT", "UPDATE", "DELETE", " FROM ")


@dataclass
class FuncFact:
    qual: str
    name: str
    file: str
    line: int
    params: list[str]
    imports: dict[str, str]
    module_aliases: dict[str, str]
    calls: list[dict]
    route: dict | None = None
    auth: bool = False
    bounded: bool = False
    observations: list[dict] = field(default_factory=list)
    effects: list[dict] = field(default_factory=list)


def module_name(rel: str) -> str:
    path = rel[:-3] if rel.endswith(".py") else rel
    if path.endswith("/__init__"):
        path = path[: -len("/__init__")]
    return path.replace("/", ".")


def parse_python(rel: str, source: str) -> list[FuncFact]:
    tree = ast.parse(source)
    module = module_name(rel)
    imports: dict[str, str] = {}
    module_aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                module_aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                local = alias.asname or alias.name
                if alias.name == "*":
                    continue
                imports[local] = f"{node.module}.{alias.name}"
                module_aliases.setdefault(local, f"{node.module}.{alias.name}")
    facts: list[FuncFact] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            facts.append(_function_fact(node, module, rel, source, imports, module_aliases, None))
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.FunctionDef):
                    facts.append(_function_fact(item, module, rel, source, imports, module_aliases, node.name))
    return facts


def _function_fact(node, module, rel, source, imports, module_aliases, class_name) -> FuncFact:
    qual = f"{module}.{class_name}.{node.name}" if class_name else f"{module}.{node.name}"
    params = [arg.arg for arg in node.args.args if arg.arg != "self"]
    route, auth = _route_and_auth(node, source)
    fact = FuncFact(
        qual=qual,
        name=node.name,
        file=rel,
        line=node.lineno,
        params=params,
        imports=dict(imports),
        module_aliases=dict(module_aliases),
        calls=[],
        route=route,
        auth=auth,
    )
    tainted, origins = set(params), {}
    _walk_block(node.body, fact, source, tainted, origins)
    fact.bounded = _has_lower_bound(node)
    if route and not auth:
        sensitive = bool(SENSITIVE_PATH.search(route["path"]) or SENSITIVE_PATH.search(node.name))
        fact.observations.append(
            {
                "rule": "APP10" if sensitive else "APP01",
                "theme": "unauthenticated",
                "title": "Unauthenticated route" if sensitive else "Route without an auth decorator",
                "stage": "auth" if sensitive else "entry",
                "exposure": "public",
                "privilege": "admin" if sensitive else "none",
                "asset": "financial" if sensitive else "internal",
                "exploitability": "missing_auth",
                "identity": False,
                "evidence": f"{route['method']} {route['path']}",
                "line": node.lineno,
                "recommendation": rule_recommendation("APP10" if sensitive else "APP01"),
            }
        )
    if route and any(re.search(r"\((?:body|request|payload)\)", call.get("evidence", "")) for call in fact.calls):
        fact.observations.append(
            {
                "rule": "APP02",
                "theme": "schema",
                "title": "Handler forwards the raw request body",
                "stage": "entry",
                "exposure": "public",
                "privilege": "none",
                "asset": "internal",
                "exploitability": "user_controlled",
                "identity": False,
                "evidence": f"{route['method']} {route['path']}",
                "line": node.lineno,
                "recommendation": rule_recommendation("APP02"),
            }
        )
    return fact


def _route_and_auth(node: ast.FunctionDef, source: str) -> tuple[dict | None, bool]:
    route = None
    auth = False
    for decorator in node.decorator_list:
        name = _dotted(decorator.func if isinstance(decorator, ast.Call) else decorator)
        if AUTH_DECORATORS.search(name) or re.search(r"(auth|login|permission|jwt|protect)", name, re.I):
            if "route" not in name.split(".")[-1]:
                auth = True
        info = _route_from_decorator(decorator)
        if info:
            route = info
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            called = _dotted(child.func).split(".")[-1]
            if called in {"verify_token", "require_user", "authenticate", "check_auth", "get_current_user"}:
                auth = True
    return route, auth


def _route_from_decorator(decorator) -> dict | None:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if not isinstance(target, ast.Attribute):
        return None
    verb = target.attr.lower()
    if verb == "route" and isinstance(decorator, ast.Call):
        path = _const(decorator.args[0]) if decorator.args else None
        methods = ["GET"]
        for keyword in decorator.keywords:
            if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple)):
                methods = [str(_const(item)).upper() for item in keyword.value.elts if _const(item)]
        if path:
            return {"path": path, "method": methods[0], "methods": methods, "framework": "python-http"}
    if verb in {"get", "post", "put", "delete", "patch", "head"} and isinstance(decorator, ast.Call) and decorator.args:
        path = _const(decorator.args[0])
        if path:
            return {"path": path, "method": verb.upper(), "methods": [verb.upper()], "framework": "python-http"}
    return None


def _walk_block(statements, fact: FuncFact, source: str, tainted: set[str], origins: dict[str, str]) -> None:
    for statement in statements:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name):
            _visit_calls(statement.value, fact, source, tainted, origins)
            if _is_tainted(statement.value, tainted):
                tainted.add(statement.targets[0].id)
                origins[statement.targets[0].id] = _unparse(statement.value)
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name) and statement.value is not None:
            _visit_calls(statement.value, fact, source, tainted, origins)
            if _is_tainted(statement.value, tainted):
                tainted.add(statement.target.id)
                origins[statement.target.id] = _unparse(statement.value)
        elif isinstance(statement, ast.Expr):
            _visit_calls(statement.value, fact, source, tainted, origins)
        elif isinstance(statement, ast.Return):
            if statement.value is not None:
                _visit_calls(statement.value, fact, source, tainted, origins)
        elif isinstance(statement, ast.If):
            _visit_calls(statement.test, fact, source, tainted, origins)
            _on_if(statement, fact, source, tainted, origins)
            _walk_block(statement.body, fact, source, tainted, origins)
            _walk_block(statement.orelse, fact, source, tainted, origins)
        elif isinstance(statement, (ast.For, ast.While)):
            _visit_calls(statement.iter if isinstance(statement, ast.For) else statement.test, fact, source, tainted, origins)
            _walk_block(statement.body, fact, source, tainted, origins)
        elif isinstance(statement, ast.With):
            for item in statement.items:
                _visit_calls(item.context_expr, fact, source, tainted, origins)
            _walk_block(statement.body, fact, source, tainted, origins)
        elif isinstance(statement, ast.Try):
            _walk_block(statement.body, fact, source, tainted, origins)
            for handler in statement.handlers:
                _walk_block(handler.body, fact, source, tainted, origins)
            _walk_block(statement.orelse, fact, source, tainted, origins)
            _walk_block(statement.finalbody, fact, source, tainted, origins)
        else:
            _visit_calls(statement, fact, source, tainted, origins)


def _visit_calls(node, fact: FuncFact, source: str, tainted: set[str], origins: dict[str, str]) -> None:
    """Record calls nested in an expression, including `requests.get(...).text`."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
        return
    if isinstance(node, ast.Call):
        _on_call(node, fact, source, tainted, origins)
    for child in ast.iter_child_nodes(node):
        _visit_calls(child, fact, source, tainted, origins)


def _on_if(statement: ast.If, fact: FuncFact, source: str, tainted: set[str], origins: dict[str, str]) -> None:
    if not _weak_role(statement.test):
        return
    privileged = []
    for child in ast.walk(ast.Module(body=statement.body, type_ignores=[])):
        if isinstance(child, ast.Call):
            name = _dotted(child.func).split(".")[-1]
            if PRIVILEGED_CALL.search(name):
                privileged.append(name)
    if not privileged:
        return
    fact.observations.append(
        {
            "rule": "APP10",
            "theme": "authz",
            "title": "Role check grants a privileged action to every non-guest identity",
            "stage": "auth",
            "exposure": "public",
            "privilege": "admin",
            "asset": "financial",
            "exploitability": "heuristic_logic",
            "identity": True,
            "evidence": _segment(source, statement) or f"if role check then {privileged[0]}()",
            "line": statement.lineno,
            "recommendation": "Delete the permissive branch. Allow the action only for an explicit administrative role, ownership, and workflow state.",
        }
    )


def _weak_role(test) -> bool:
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
        return False
    value = _const(test.comparators[0])
    if not isinstance(value, str):
        return False
    left = _dotted(test.left)
    if "role" not in left and "auth" not in left:
        return False
    op = test.ops[0]
    lowered = value.lower()
    if isinstance(op, ast.NotEq) and lowered in {"guest", "anonymous", "unauthenticated"}:
        return True
    if isinstance(op, ast.Eq) and lowered in {"user", "member", "authenticated", "customer"}:
        return True
    return False


def _on_call(call: ast.Call, fact: FuncFact, source: str, tainted: set[str], origins: dict[str, str]) -> None:
    dotted = _dotted(call.func)
    leaf = dotted.split(".")[-1]
    evidence = _segment(source, call) or dotted
    receiver = dotted.rsplit(".", 1)[0] if "." in dotted else None
    if isinstance(call.func, ast.Name):
        fact.calls.append({"name": call.func.id, "receiver": None, "line": call.lineno, "evidence": evidence})
    elif receiver:
        fact.calls.append({"name": leaf, "receiver": receiver.split(".")[0], "line": call.lineno, "evidence": evidence})
    _classify_sink(call, fact, tainted, origins, evidence, leaf, dotted)


def _classify_sink(call, fact, tainted, origins, evidence, leaf, dotted) -> None:
    arg_texts = [_unparse(arg) for arg in call.args]
    tainted_arg = any(_is_tainted(arg, tainted) for arg in list(call.args) + [kw.value for kw in call.keywords])
    blob = " ".join(arg_texts + [origins.get(_name_of(arg), "") for arg in call.args])
    lowered = dotted.lower()
    if any(host in blob for host in METADATA_HOSTS) or any(host in evidence for host in METADATA_HOSTS):
        credential = any(part in blob for part in ("iam", "security-credentials", "identity", "token"))
        fact.effects.append(
            {
                "kind": "metadata",
                "credential": credential,
                "line": call.lineno,
                "evidence": evidence,
            }
        )
        fact.observations.append(
            {
                "rule": "APP08",
                "theme": "metadata",
                "title": "Workload reads the instance metadata service",
                "stage": "credential",
                "exposure": "internal",
                "privilege": "credential",
                "asset": "credential",
                "exploitability": "misconfiguration",
                "identity": False,
                "evidence": evidence,
                "line": call.lineno,
                "recommendation": rule_recommendation("APP08"),
            }
        )
        return
    http = any(token in lowered for token in ("requests.", "httpx.", "urllib", "fetch"))
    if http and leaf in {"get", "post", "put", "delete", "patch", "request", "urlopen"} and tainted_arg:
        fact.observations.append(
            {
                "rule": "APP08",
                "theme": "ssrf",
                "title": "Outbound request is built from caller-controlled input",
                "stage": "exploit",
                "exposure": "public",
                "privilege": "ssrf",
                "asset": "internal",
                "exploitability": "user_controlled",
                "identity": False,
                "evidence": evidence,
                "line": call.lineno,
                "recommendation": rule_recommendation("APP08"),
            }
        )
    if leaf in {"execute", "executemany", "executemany".lower()} or leaf in {"raw", "query"}:
        sqlish = any(word in blob.upper() for word in SQL_WORDS) or any(word in evidence.upper() for word in SQL_WORDS)
        if tainted_arg and sqlish and leaf in {"execute", "executemany", "raw", "query"}:
            table = _table_name(blob + " " + evidence)
            fact.effects.append({"kind": "sql", "table": table, "line": call.lineno, "evidence": evidence})
            fact.observations.append(
                {
                    "rule": "APP09",
                    "theme": "sqli",
                    "title": "Query text is concatenated with caller-controlled input",
                    "stage": "exploit",
                    "exposure": "public",
                    "privilege": "data",
                    "asset": "sensitive" if _sensitive_table(table, blob) else "internal",
                    "exploitability": "user_controlled",
                    "identity": False,
                    "evidence": evidence,
                    "line": call.lineno,
                    "recommendation": rule_recommendation("APP09"),
                    "table": table,
                }
            )
    if leaf in {"get_object", "put_object", "download_file", "upload_file"} or "boto3" in lowered:
        bucket = _keyword_const(call, "Bucket") or _keyword_const(call, "bucket")
        if bucket or leaf in {"get_object", "put_object", "download_file", "upload_file"}:
            fact.effects.append({"kind": "bucket", "bucket": bucket or "object-storage", "line": call.lineno, "evidence": evidence})
    if leaf in {"eval", "exec"} or "subprocess" in lowered or leaf in {"system", "popen"} or "shell=True" in evidence:
        if leaf in {"eval", "exec", "system", "popen"} or "subprocess" in lowered or "shell=True" in evidence:
            fact.observations.append(
                {
                    "rule": "APP05",
                    "theme": "rce",
                    "title": "Dynamic execution primitive",
                    "stage": "exploit",
                    "exposure": "public",
                    "privilege": "rce",
                    "asset": "production",
                    "exploitability": "user_controlled" if tainted_arg else "misconfiguration",
                    "identity": False,
                    "evidence": evidence,
                    "line": call.lineno,
                    "recommendation": rule_recommendation("APP05"),
                }
            )
    if "pickle" in lowered and leaf in {"loads", "load"}:
        fact.observations.append(
            {
                "rule": "APP05",
                "theme": "rce",
                "title": "Unsafe deserialization primitive",
                "stage": "exploit",
                "exposure": "public",
                "privilege": "rce",
                "asset": "production",
                "exploitability": "user_controlled" if tainted_arg else "misconfiguration",
                "identity": False,
                "evidence": evidence,
                "line": call.lineno,
                "recommendation": rule_recommendation("APP05"),
            }
        )
    if leaf in {"load", "unsafe_load"} and "yaml" in lowered and "safeloader" not in evidence.lower():
        fact.observations.append(
            {
                "rule": "APP05",
                "theme": "rce",
                "title": "YAML loader can construct objects",
                "stage": "exploit",
                "exposure": "public",
                "privilege": "rce",
                "asset": "production",
                "exploitability": "user_controlled" if tainted_arg else "misconfiguration",
                "identity": False,
                "evidence": evidence,
                "line": call.lineno,
                "recommendation": rule_recommendation("APP05"),
            }
        )
    if "jwt" in lowered and leaf in {"decode", "verify"} and re.search(r"verify\s*=\s*False", evidence):
        fact.observations.append(
            {
                "rule": "APP03",
                "theme": "authz",
                "title": "Token signature verification is disabled",
                "stage": "auth",
                "exposure": "public",
                "privilege": "admin",
                "asset": "credential",
                "exploitability": "missing_auth",
                "identity": True,
                "evidence": evidence,
                "line": call.lineno,
                "recommendation": rule_recommendation("APP03"),
            }
        )


def _money_observation(fact: FuncFact, source_unused: str) -> None:
    if not MONEY_NAME.search(fact.name):
        return
    if not (set(fact.params) & MONEY_PARAMS):
        return
    if fact.bounded:
        return
    fact.observations.append(
        {
            "rule": "APP10",
            "theme": "logic",
            "title": "Wallet or credit function has no visible lower bound",
            "stage": "exploit",
            "exposure": "public",
            "privilege": "logic",
            "asset": "financial",
            "exploitability": "heuristic_logic",
            "identity": False,
            "evidence": f"def {fact.name}({', '.join(fact.params)})",
            "line": fact.line,
            "recommendation": "Constrain the amount to a positive range at the boundary, or delete the credit path if it should not exist.",
        }
    )


def resolve_python(model: RepoModel, facts: list[FuncFact]) -> None:
    by_qual = {}
    by_name: dict[str, list[str]] = {}
    for fact in facts:
        _money_observation(fact, "")
        node_id = model.node(
            "function",
            fact.name,
            file=fact.file,
            line=fact.line,
            lane="service",
            language="python",
            properties={"qual": fact.qual, "params": fact.params, "auth": fact.auth},
        )
        by_qual[fact.qual] = node_id
        by_name.setdefault(fact.name, []).append(fact.qual)
        if fact.route:
            method = fact.route["method"]
            path = fact.route["path"]
            endpoint = model.node(
                "endpoint",
                f"{method} {path}",
                file=fact.file,
                line=fact.line,
                lane="entry",
                language="python",
                receives=f"{method} {path}",
                properties={
                    "method": method,
                    "path": path,
                    "auth": fact.auth,
                    "framework": fact.route["framework"],
                    "handler": fact.name,
                },
            )
            model.edge(endpoint, node_id, "ROUTES_TO", file=fact.file, line=fact.line, evidence=f"{method} {path}")
            model.nodes[node_id]["receives"] = f"{method} {path}"
        for observation in fact.observations:
            model.observe(
                rule=observation["rule"],
                theme=observation["theme"],
                title=observation["title"],
                stage=observation["stage"],
                node_id=node_id,
                file=fact.file,
                line=observation.get("line", fact.line),
                evidence=observation["evidence"],
                recommendation=observation["recommendation"],
                exposure=observation["exposure"],
                privilege=observation["privilege"],
                asset=observation["asset"],
                exploitability=observation["exploitability"],
                identity=observation.get("identity", False),
                table=observation.get("table"),
            )
        for effect in fact.effects:
            _materialize_effect(model, node_id, fact, effect)
    for fact in facts:
        source_id = by_qual[fact.qual]
        for call in fact.calls:
            target, confidence = _resolve_call(fact, call, by_qual, by_name)
            if target and target != source_id:
                model.edge(
                    source_id,
                    target,
                    "CALLS",
                    file=fact.file,
                    line=call["line"],
                    evidence=call["evidence"],
                    confidence=confidence,
                )


def _materialize_effect(model: RepoModel, func_id: str, fact: FuncFact, effect: dict) -> None:
    if effect["kind"] == "metadata":
        cloud = model.node(
            "cloud",
            "Instance metadata service",
            lane="credential",
            unique=True,
            properties={"service": "imds"},
        )
        model.edge(func_id, cloud, "FLOWS_TO", file=fact.file, line=effect["line"], evidence=effect["evidence"])
        if effect.get("credential"):
            secret = model.node(
                "secret",
                "Cloud role credentials",
                lane="credential",
                unique=True,
                properties={"source": "metadata"},
            )
            model.edge(cloud, secret, "FLOWS_TO", file=fact.file, line=effect["line"], evidence=effect["evidence"])
            model.observe(
                rule="APP03",
                theme="credential",
                title="Metadata read yields cloud role credentials",
                stage="credential",
                node_id=secret,
                file=fact.file,
                line=effect["line"],
                evidence=effect["evidence"],
                recommendation=rule_recommendation("APP03"),
                exposure="internal",
                privilege="credential",
                asset="credential",
                exploitability="misconfiguration",
                identity=False,
            )
    elif effect["kind"] == "bucket":
        bucket = model.node(
            "bucket",
            effect["bucket"],
            lane="data",
            unique=True,
            properties={"provider": "s3"},
        )
        model.edge(func_id, bucket, "READS", file=fact.file, line=effect["line"], evidence=effect["evidence"])
    elif effect["kind"] == "sql":
        table = effect.get("table") or "SQL database"
        store = model.node(
            "datastore",
            f"Table {table}" if effect.get("table") else "SQL database",
            lane="data",
            unique=True,
            properties={"table": effect.get("table"), "sensitive": _sensitive_table(effect.get("table"), effect.get("evidence", ""))},
        )
        model.edge(func_id, store, "READS", file=fact.file, line=effect["line"], evidence=effect["evidence"])


def _resolve_call(fact: FuncFact, call: dict, by_qual: dict, by_name: dict) -> tuple[str | None, str]:
    """Return the callee and whether the link was written in this file or resolved.

    A call in the same file is EXTRACTED. A call reached through an import or a
    unique name elsewhere is INFERRED: the analyzer connected it.
    """
    name = call["name"]
    if name in BUILTIN_CALLS:
        return None, "EXTRACTED"
    here = fact.qual.rsplit(".", 1)[0]
    receiver = call.get("receiver")
    if receiver:
        module = fact.module_aliases.get(receiver)
        if module:
            direct = by_qual.get(f"{module}.{name}")
            if direct:
                return direct, "INFERRED"
            parent = module.rsplit(".", 1)[0]
            resolved = by_qual.get(f"{parent}.{name}")
            return resolved, "INFERRED"
        return None, "EXTRACTED"
    imported = fact.imports.get(name)
    if imported and imported in by_qual:
        return by_qual[imported], "INFERRED"
    candidates = by_name.get(name, [])
    if len(candidates) == 1:
        qual = candidates[0]
        same = qual.rsplit(".", 1)[0] == here
        return by_qual[qual], "EXTRACTED" if same else "INFERRED"
    same_module = [qual for qual in candidates if qual.rsplit(".", 1)[0] == here]
    if len(same_module) == 1:
        return by_qual[same_module[0]], "EXTRACTED"
    return None, "EXTRACTED"


def analyze_javascript(model: RepoModel, rel: str, source: str) -> None:
    route_re = re.compile(
        r"""(?P<obj>[A-Za-z_$][\w$]*)\.(?P<verb>get|post|put|delete|patch|all)\(\s*['\"](?P<path>[^'\"]+)['\"]""",
        re.I,
    )
    for match in route_re.finditer(source):
        line = source[: match.start()].count("\n") + 1
        verb = match.group("verb").upper()
        path = match.group("path")
        body = _after_braces(source, match.end())
        handler = model.node(
            "function",
            f"{verb} {path}",
            file=rel,
            line=line,
            lane="service",
            language="javascript",
            receives=f"{verb} {path}",
        )
        endpoint = model.node(
            "endpoint",
            f"{verb} {path}",
            file=rel,
            line=line,
            lane="entry",
            language="javascript",
            receives=f"{verb} {path}",
            properties={"method": verb, "path": path, "auth": "auth" in body.lower()[:200], "framework": "express-like", "handler": f"{verb} {path}"},
        )
        # Endpoint and handler share a name but not an id because handler is not unique-by-name
        # when created first. Link them.
        model.edge(endpoint, handler, "ROUTES_TO", file=rel, line=line, evidence=match.group(0)[:180])
        if not model.nodes[endpoint]["properties"].get("auth") and SENSITIVE_PATH.search(path):
            model.observe(
                rule="APP10",
                theme="unauthenticated",
                title="Unauthenticated route",
                stage="auth",
                node_id=handler,
                file=rel,
                line=line,
                evidence=f"{verb} {path}",
                recommendation=rule_recommendation("APP10"),
                exposure="public",
                privilege="admin",
                asset="internal",
                exploitability="missing_auth",
                identity=False,
            )
        if re.search(r"\b(fetch|axios|http\.get|got)\s*\(\s*[A-Za-z_$]", body):
            model.observe(
                rule="APP08",
                theme="ssrf",
                title="Outbound request is built from caller-controlled input",
                stage="exploit",
                node_id=handler,
                file=rel,
                line=line,
                evidence=_first_line(body, r"fetch|axios|http\.get|got"),
                recommendation=rule_recommendation("APP08"),
                exposure="public",
                privilege="ssrf",
                asset="internal",
                exploitability="user_controlled",
                identity=False,
            )
        if re.search(r"\b(eval|Function|child_process|exec)\s*\(", body):
            model.observe(
                rule="APP05",
                theme="rce",
                title="Dynamic execution primitive",
                stage="exploit",
                node_id=handler,
                file=rel,
                line=line,
                evidence=_first_line(body, r"eval|Function|child_process|exec"),
                recommendation=rule_recommendation("APP05"),
                exposure="public",
                privilege="rce",
                asset="production",
                exploitability="user_controlled",
                identity=False,
            )


def analyze_java(model: RepoModel, rel: str, source: str) -> None:
    mapping = re.compile(
        r"@(Get|Post|Put|Delete|Patch|Request)Mapping\(\s*(?:value\s*=\s*)?\"([^\"]+)\"",
        re.I,
    )
    for match in mapping.finditer(source):
        line = source[: match.start()].count("\n") + 1
        verb = match.group(1).upper()
        if verb == "REQUEST":
            verb = "GET"
        path = match.group(2)
        window = source[max(0, match.start() - 250) : match.start()]
        body = _after_braces(source, match.end())
        auth = bool(re.search(r"PreAuthorize|RolesAllowed|Secured|Authorize", window + body[:120]))
        handler_name = _next_method(source, match.end()) or f"{verb} {path}"
        handler = model.node("function", handler_name, file=rel, line=line, lane="service", language="java", receives=f"{verb} {path}")
        endpoint = model.node(
            "endpoint",
            f"{verb} {path}",
            file=rel,
            line=line,
            lane="entry",
            language="java",
            receives=f"{verb} {path}",
            properties={"method": verb, "path": path, "auth": auth, "framework": "spring", "handler": handler_name},
        )
        model.edge(endpoint, handler, "ROUTES_TO", file=rel, line=line, evidence=match.group(0))
        if not auth and SENSITIVE_PATH.search(path + handler_name):
            model.observe(
                rule="APP10",
                theme="unauthenticated",
                title="Unauthenticated route",
                stage="auth",
                node_id=handler,
                file=rel,
                line=line,
                evidence=f"{verb} {path}",
                recommendation=rule_recommendation("APP10"),
                exposure="public",
                privilege="admin",
                asset="internal",
                exploitability="missing_auth",
                identity=False,
            )
        if re.search(r"new\s+URL\s*\(\s*[A-Za-z_]", body) or re.search(r"\.openStream\s*\(", body):
            model.observe(
                rule="APP08",
                theme="ssrf",
                title="Outbound request is built from caller-controlled input",
                stage="exploit",
                node_id=handler,
                file=rel,
                line=line,
                evidence=_first_line(body, r"new\s+URL|openStream"),
                recommendation=rule_recommendation("APP08"),
                exposure="public",
                privilege="ssrf",
                asset="internal",
                exploitability="user_controlled",
                identity=False,
            )


def analyze_go(model: RepoModel, rel: str, source: str) -> None:
    handles = re.finditer(r'http\.HandleFunc\(\s*"([^"]+)"\s*,\s*(\w+)\s*\)', source)
    funcs = {match.group(1): match.start() for match in re.finditer(r"func\s+(\w+)\s*\(", source)}
    for match in handles:
        path = match.group(1)
        handler_name = match.group(2)
        line = source[: match.start()].count("\n") + 1
        body = ""
        if handler_name in funcs:
            body = _after_braces(source, funcs[handler_name])
        handler = model.node("function", handler_name, file=rel, line=line, lane="service", language="go", receives=f"GET {path}")
        endpoint = model.node(
            "endpoint",
            f"GET {path}",
            file=rel,
            line=line,
            lane="entry",
            language="go",
            receives=f"GET {path}",
            properties={"method": "GET", "path": path, "auth": False, "framework": "net/http", "handler": handler_name},
        )
        model.edge(endpoint, handler, "ROUTES_TO", file=rel, line=line, evidence=match.group(0))
        if re.search(r"exec\.Command\s*\(", body):
            model.observe(
                rule="APP05",
                theme="rce",
                title="Dynamic execution primitive",
                stage="exploit",
                node_id=handler,
                file=rel,
                line=line,
                evidence=_first_line(body, r"exec\.Command"),
                recommendation=rule_recommendation("APP05"),
                exposure="public",
                privilege="rce",
                asset="production",
                exploitability="user_controlled",
                identity=False,
            )


def analyze_csharp(model: RepoModel, rel: str, source: str) -> None:
    pattern = re.compile(r"\[Http(Get|Post|Put|Delete|Patch)(?:\(\s*\"([^\"]*)\"\s*\))?\]", re.I)
    for match in pattern.finditer(source):
        line = source[: match.start()].count("\n") + 1
        verb = match.group(1).upper()
        path = match.group(2) or "/"
        window = source[match.end() : match.end() + 400]
        name_match = re.search(r"\b(\w+)\s*\(", window)
        handler_name = name_match.group(1) if name_match else f"{verb} {path}"
        auth = "Authorize" in source[max(0, match.start() - 200) : match.start()]
        handler = model.node("function", handler_name, file=rel, line=line, lane="service", language="csharp", receives=f"{verb} {path}")
        endpoint = model.node(
            "endpoint",
            f"{verb} {path}",
            file=rel,
            line=line,
            lane="entry",
            language="csharp",
            receives=f"{verb} {path}",
            properties={"method": verb, "path": path, "auth": auth, "framework": "aspnet", "handler": handler_name},
        )
        model.edge(endpoint, handler, "ROUTES_TO", file=rel, line=line, evidence=match.group(0))
        if (not auth) and SENSITIVE_PATH.search(path + handler_name):
            model.observe(
                rule="APP10",
                theme="unauthenticated",
                title="Unauthenticated route",
                stage="auth",
                node_id=handler,
                file=rel,
                line=line,
                evidence=f"{verb} {path}",
                recommendation=rule_recommendation("APP10"),
                exposure="public",
                privilege="admin",
                asset="internal",
                exploitability="missing_auth",
                identity=False,
            )


def analyze_php(model: RepoModel, rel: str, source: str) -> None:
    pattern = re.compile(r"Route::(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]", re.I)
    for match in pattern.finditer(source):
        line = source[: match.start()].count("\n") + 1
        verb = match.group(1).upper()
        path = match.group(2)
        body = source[match.end() : match.end() + 500]
        handler = model.node("function", f"{verb} {path}", file=rel, line=line, lane="service", language="php", receives=f"{verb} {path}")
        endpoint = model.node(
            "endpoint",
            f"{verb} {path}",
            file=rel,
            line=line,
            lane="entry",
            language="php",
            receives=f"{verb} {path}",
            properties={"method": verb, "path": path, "auth": False, "framework": "php", "handler": f"{verb} {path}"},
        )
        model.edge(endpoint, handler, "ROUTES_TO", file=rel, line=line, evidence=match.group(0))
        if re.search(r"(mysqli_query|mysql_query|->query)\s*\(.*(\$_(GET|POST|REQUEST)|\.\s*\$)", body, re.S):
            model.observe(
                rule="APP09",
                theme="sqli",
                title="Query text is concatenated with caller-controlled input",
                stage="exploit",
                node_id=handler,
                file=rel,
                line=line,
                evidence=_first_line(body, r"mysqli_query|mysql_query|->query"),
                recommendation=rule_recommendation("APP09"),
                exposure="public",
                privilege="data",
                asset="sensitive",
                exploitability="user_controlled",
                identity=False,
            )


def _materialize_polyglot_sql(model: RepoModel) -> None:
    already = set()
    for edge in model.edges:
        target = model.nodes.get(edge["target"])
        if edge["kind"] == "READS" and target and target["kind"] == "datastore":
            already.add(edge["source"])
    for observation in list(model.observations):
        node_id = observation.get("node_id")
        if observation.get("theme") != "sqli" or not node_id or node_id in already:
            continue
        store = model.node("datastore", "SQL database", lane="data", unique=True, properties={"sensitive": True})
        model.edge(node_id, store, "READS", file=observation.get("file"), line=observation.get("line"), evidence=observation.get("evidence", ""))


def _const(node):
    if isinstance(node, ast.Constant):
        return node.value
    return None


def _keyword_const(call: ast.Call, name: str):
    for keyword in call.keywords:
        if keyword.arg == name:
            return _const(keyword.value)
    return None


def _dotted(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    if isinstance(node, ast.Subscript):
        return _dotted(node.value)
    return ""


def _name_of(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _is_tainted(node, tainted: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in tainted
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.FormattedValue, ast.Subscript)):
        return any(_is_tainted(child, tainted) for child in ast.iter_child_nodes(node))
    if isinstance(node, ast.Call):
        dotted = _dotted(node.func)
        if dotted.endswith(".get") or dotted.endswith("get_json") or "request" in dotted or "args" in dotted or "body" in dotted:
            return True
        return any(_is_tainted(arg, tainted) for arg in node.args)
    if isinstance(node, ast.Attribute):
        return _is_tainted(node.value, tainted) or "request" in _dotted(node)
    return any(_is_tainted(child, tainted) for child in ast.iter_child_nodes(node))


def _unparse(node) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _segment(source: str, node) -> str:
    try:
        return ast.get_source_segment(source, node) or ""
    except Exception:
        return ""


def _has_lower_bound(fn: ast.AST) -> bool:
    for child in ast.walk(fn):
        if not isinstance(child, ast.Compare):
            continue
        for op, comp in zip(child.ops, child.comparators):
            if isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)) and isinstance(comp, ast.Constant) and comp.value == 0:
                return True
    return False


def _table_name(text: str) -> str | None:
    match = re.search(r"\bFROM\s+([A-Za-z_][A-Za-z0-9_]*)", text, re.I)
    if match:
        return match.group(1)
    return None


def _sensitive_table(table: str | None, blob: str) -> bool:
    haystack = f"{table or ''} {blob}".lower()
    return any(token in haystack for token in ("user", "customer", "password", "pii", "payment", "card", "receipt"))


def _after_braces(source: str, start: int) -> str:
    index = source.find("{", start)
    if index < 0:
        return source[start : start + 400]
    depth = 0
    for cursor in range(index, min(len(source), index + 4000)):
        char = source[cursor]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[index : cursor + 1]
    return source[index : index + 800]


def _next_method(source: str, start: int) -> str | None:
    match = re.search(r"\b(?:public|protected|private)\s+[\w<>,\s\[\]]+\s+(\w+)\s*\(", source[start : start + 300])
    return match.group(1) if match else None


def _first_line(body: str, pattern: str) -> str:
    for line in body.splitlines():
        if re.search(pattern, line):
            return line.strip()[:220]
    return body.strip()[:220]

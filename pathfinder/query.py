"""Attack-path search over the analyzed graph.

A hypothesis names an attacker objective: start somewhere, reach something,
optionally passing through roles, and optionally requiring that a control
is absent. The walk is taken from edges the analyzer already proved.
The result names the walk and the edge to delete or constrain.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from pathlib import Path

import yaml

from pathfinder.model import FOLLOW_EDGES
from pathfinder.scoring import score_path

RULES_DIR = Path(__file__).resolve().parent / "rules"
MAX_PATHS = 12
MAX_EXPAND = 8000

CANON = {
    "internet": "INTERNET",
    "public-endpoint": "PUBLIC_ENDPOINT",
    "public_endpoint": "PUBLIC_ENDPOINT",
    "public-api": "PUBLIC_API",
    "public_api": "PUBLIC_API",
    "api": "API",
    "application": "APPLICATION",
    "service": "SERVICE",
    "container": "CONTAINER",
    "user": "USER",
    "secret": "SECRET",
    "secrets": "SECRET",
    "pii-database": "PII_DATABASE",
    "pii_database": "PII_DATABASE",
    "pii": "PII_DATABASE",
    "customer-data": "PII_DATABASE",
    "pci-data": "PCI_DATA",
    "pci_data": "PCI_DATA",
    "pci": "PCI_DATA",
    "financial-data": "FINANCIAL_DATA",
    "financial_data": "FINANCIAL_DATA",
    "financial": "FINANCIAL_DATA",
    "payment-db": "PAYMENT_DB",
    "payment_db": "PAYMENT_DB",
    "payment-api": "PAYMENT_API",
    "payment_api": "PAYMENT_API",
    "database": "DATABASE",
    "iam-admin": "IAM_ADMIN",
    "iam_admin": "IAM_ADMIN",
    "admin-policy": "ADMIN_POLICY",
    "admin_policy": "ADMIN_POLICY",
    "administratoraccess": "ADMIN_POLICY",
    "admin-function": "ADMIN_FUNCTION",
    "admin_function": "ADMIN_FUNCTION",
    "admin": "ADMIN_FUNCTION",
    "iam-role": "IAM_ROLE",
    "iam_role": "IAM_ROLE",
    "backup": "BACKUP",
    "storage": "STORAGE",
    "production": "PRODUCTION",
    "source-code": "SOURCE_CODE",
    "source_code": "SOURCE_CODE",
    "source": "SOURCE_CODE",
    "privileged": "PRIVILEGED",
    "privileged-service": "PRIVILEGED",
    "mfa": "MFA",
    "authorization_check": "AUTHORIZATION_CHECK",
    "authorization-check": "AUTHORIZATION_CHECK",
    "no_authz_check": "NO_AUTHZ_CHECK",
    "no-authz-check": "NO_AUTHZ_CHECK",
    "user_input_reachable": "USER_INPUT_REACHABLE",
    "user-input-reachable": "USER_INPUT_REACHABLE",
}

PII_WORDS = re.compile(r"pii|ssn|passport|patient|\bemail\b|customer|\buser", re.I)
PCI_WORDS = re.compile(r"pci|\bpan\b|\bcvv\b|cardholder|card_number|payment.?card", re.I)
MONEY_WORDS = re.compile(r"payment|invoice|ledger|wallet|bank|\biban\b|receipt|financial|billing", re.I)
ADMIN_WORDS = re.compile(r"admin|administrator|impersonat|approve|grant_role|refund|privilege", re.I)
BACKUP_WORDS = re.compile(r"backup|snapshot|\bdump\b|export", re.I)
SECRET_WORDS = re.compile(r"secret|password|passwd|token|api[_-]?key|private[_-]?key|credential", re.I)
DEBUG_WORDS = re.compile(r"debug|actuator|console|phpinfo|(^|/)env($|/)", re.I)
GRAPH_QUERY = re.compile(
    r"^\s*(?P<start>[A-Za-z0-9_-]+)\s*(?:-\[\*(?:\.\.(?P<hops>\d+))?\]->|->)\s*(?P<target>[A-Za-z0-9_-]+)\s*$"
)


class QueryError(Exception):
    pass


def canon(value: str) -> str:
    text = str(value).strip()
    mapped = CANON.get(text.lower()) or CANON.get(text.lower().replace(" ", "-").replace("_", "-"))
    if mapped:
        return mapped
    return re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_").upper()


def normalize(raw: dict) -> dict:
    if not isinstance(raw, dict):
        raise QueryError("A hypothesis must be a mapping")
    start = _as_list(raw.get("start") or raw.get("entry") or raw.get("from"))
    target = _as_list(raw.get("target") or raw.get("targets") or raw.get("to"))
    through = _as_list(raw.get("through"))
    if not start or not target:
        raise QueryError("A hypothesis needs a start and a target")
    try:
        hops = int(raw.get("max_hops") or 12)
    except (TypeError, ValueError) as exc:
        raise QueryError("max_hops must be an integer") from exc
    hops = min(max(hops, 1), 12)
    return {
        "name": str(raw.get("name") or "custom"),
        "summary": str(raw.get("summary") or ""),
        "start": [canon(item) for item in start],
        "through": [canon(item) for item in through],
        "target": [canon(item) for item in target],
        "conditions": [canon(item) for item in _as_list(raw.get("conditions"))],
        "must_not_have": [canon(item) for item in _as_list(raw.get("must_not_have"))],
        "edges": [str(item).upper() for item in _as_list(raw.get("edges"))] or list(FOLLOW_EDGES),
        "severity": str(raw.get("severity") or ""),
        "max_hops": hops,
        "frameworks": [str(item) for item in _as_list(raw.get("frameworks"))],
    }


def load_rule_file(path: Path) -> dict:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise QueryError(f"{path} is not valid YAML: {exc}") from exc
    hypothesis = normalize(raw or {})
    hypothesis["source"] = str(path)
    return hypothesis


def builtin_hypotheses() -> list[dict]:
    found = []
    if not RULES_DIR.is_dir():
        return found
    for path in sorted(RULES_DIR.glob("*.yaml")):
        found.append(load_rule_file(path))
    return found


def repo_hypotheses(root: Path | None) -> list[dict]:
    if root is None:
        return []
    folder = Path(root) / "rules"
    if not folder.is_dir():
        return []
    found = []
    for path in sorted(folder.rglob("*.yaml")):
        try:
            found.append(load_rule_file(path))
        except QueryError:
            continue
    return found


def hypothesis_by_name(name: str, root: Path | None = None) -> dict:
    key = name.strip().lower().replace("_", "-")
    pool = repo_hypotheses(root) + builtin_hypotheses()
    for item in pool:
        stem = Path(item.get("source") or "").stem.lower()
        title = item["name"].lower().replace("_", "-").replace(" ", "-")
        if key in {stem, title, item["name"].lower()}:
            return item
    known = ", ".join(sorted({Path(item.get("source") or item["name"]).stem for item in builtin_hypotheses()}))
    raise QueryError(f"Unknown hunt '{name}'. Known hunts: {known}")


def translate(question: str) -> dict:
    """Map a plain question onto a start and a target. No model call."""
    text = question.lower()
    if any(word in text for word in ("ransomware", "backup", "snapshot")):
        return hypothesis_by_name("ransomware")
    if "privilege" in text and "escalat" in text:
        return hypothesis_by_name("privilege-escalation")
    if "lateral" in text:
        return hypothesis_by_name("lateral-movement")
    start = "INTERNET"
    if "public api" in text or "public endpoint" in text:
        start = "PUBLIC_ENDPOINT"
    elif "application code" in text or text.startswith("application"):
        start = "APPLICATION"
    elif "container" in text:
        start = "CONTAINER"
    target = "SECRET"
    if any(word in text for word in ("pii", "personal", "customer data", "customer record")):
        target = "PII_DATABASE"
    elif any(word in text for word in ("financial", "payment", "pci", "card")):
        target = "FINANCIAL_DATA" if "pci" not in text and "card" not in text else "PCI_DATA"
    elif any(word in text for word in ("iam", "aws admin", "administratoraccess", "admin permission")):
        target = "IAM_ADMIN"
    elif "domain admin" in text or "admin function" in text or "admin" in text:
        target = "ADMIN_FUNCTION"
    elif any(word in text for word in ("source code", "repository", "git")):
        target = "SOURCE_CODE"
    elif any(word in text for word in ("production", "deploy")):
        target = "PRODUCTION"
    elif "database" in text:
        target = "DATABASE"
    elif "secret" in text or "credential" in text:
        target = "SECRET"
    return normalize(
        {
            "name": "Question",
            "summary": question.strip(),
            "start": [start],
            "target": [target],
            "frameworks": ["Attack path question"],
        }
    )


def parse_graph_query(expression: str) -> dict:
    match = GRAPH_QUERY.match(expression.strip())
    if not match:
        raise QueryError("Graph query must look like PUBLIC_ENDPOINT -[*..12]-> SECRET")
    hops = match.group("hops") or "12"
    return normalize(
        {
            "name": expression.strip(),
            "start": [match.group("start")],
            "target": [match.group("target")],
            "max_hops": int(hops),
        }
    )


def search(result: dict, hypothesis: dict) -> dict:
    prepared = normalize(hypothesis)
    nodes = {node["id"]: node for node in result.get("nodes") or []}
    observations = result.get("observations") or []
    obs_by: dict[str, list[dict]] = defaultdict(list)
    for item in observations:
        if item.get("node_id"):
            obs_by[item["node_id"]].append(item)
    roles = {node_id: roles_for(node, obs_by[node_id]) for node_id, node in nodes.items()}
    controls = {node_id: controls_for(node, obs_by[node_id]) for node_id, node in nodes.items()}
    allowed = set(prepared["edges"])
    graph: dict[str, list[str]] = defaultdict(list)
    for edge in result.get("edges") or []:
        if edge.get("kind") in allowed and edge.get("source") in nodes and edge.get("target") in nodes:
            graph[edge["source"]].append(edge["target"])
    starts = [node_id for node_id, role in roles.items() if _matches(nodes[node_id], role, prepared["start"])]
    walks: list[list[str]] = []
    expanded = 0
    for start in starts:
        if len(walks) >= MAX_PATHS or expanded >= MAX_EXPAND:
            break
        queue = deque([(start, [start])])
        while queue and len(walks) < MAX_PATHS and expanded < MAX_EXPAND:
            current, path = queue.popleft()
            expanded += 1
            if len(path) >= 2 and _matches(nodes[current], roles[current], prepared["target"]):
                if _through(path, nodes, roles, prepared["through"]) and _conditions(path, obs_by, roles, controls, prepared["conditions"]) and _missing(path, roles, controls, prepared["must_not_have"]):
                    walks.append(path)
                continue
            if len(path) > prepared["max_hops"]:
                continue
            for nxt in graph.get(current, []):
                if nxt in path:
                    continue
                queue.append((nxt, path + [nxt]))
    unique: list[list[str]] = []
    seen = set()
    for walk in walks:
        key = tuple(walk)
        if key in seen:
            continue
        seen.add(key)
        unique.append(walk)
    paths = [_materialize(walk, nodes, obs_by, roles, controls, prepared) for walk in unique]
    paths.sort(key=lambda item: (-item["score"], len(item["labels"])))
    return {
        "name": prepared["name"],
        "summary": prepared["summary"],
        "question": _question(prepared),
        "start": prepared["start"],
        "target": prepared["target"],
        "through": prepared["through"],
        "conditions": prepared["conditions"],
        "must_not_have": prepared["must_not_have"],
        "declared_severity": prepared["severity"],
        "frameworks": prepared["frameworks"],
        "found": len(paths),
        "paths": paths[:MAX_PATHS],
    }


def attach_search(result: dict) -> dict:
    root = Path(result["root"]) if result.get("root") else None
    hypotheses = []
    for item in builtin_hypotheses() + repo_hypotheses(root):
        try:
            hypotheses.append(search(result, item))
        except QueryError:
            continue
    from pathfinder.agents import review

    notes = review(result, hypotheses)
    result["hypotheses"] = hypotheses
    result["agent_reviews"] = notes
    result["frameworks"] = framework_catalog(hypotheses, notes)
    scorecard = result.setdefault("scorecard", {})
    reached = [item for item in hypotheses if item["found"]]
    scorecard["objectives"] = len(reached)
    scorecard["objective_paths"] = sum(item["found"] for item in hypotheses)
    return result


def framework_catalog(hypotheses: list[dict], notes: list[dict]) -> list[dict]:
    matched = {name for item in hypotheses if item["found"] for name in item.get("frameworks") or []}
    matched.update(note.get("framework") for note in notes if note.get("framework"))
    catalog = []
    for framework in FRAMEWORKS:
        catalog.append(
            {
                "id": framework["id"],
                "name": framework["name"],
                "reviewed": True,
                "matched": framework["name"] in matched or framework["id"] in matched,
                "focus": framework["focus"],
            }
        )
    return catalog


def format_hypotheses(items: list[dict]) -> str:
    blocks = []
    for item in items:
        header = item["name"]
        if item.get("question"):
            header += f"\n{item['question']}"
        if not item["paths"]:
            blocks.append(f"{header}\nNo path matched this objective.")
            continue
        lines = [header, f"Found {item['found']} path{'s' if item['found'] != 1 else ''}"]
        for path in item["paths"]:
            lines.append("")
            lines.append("\n \u2193\n".join(path["labels"]))
            lines.append(f"Risk: {path['band']}")
            if path.get("missing_controls"):
                lines.append("Missing controls: " + ", ".join(path["missing_controls"]))
            if path.get("frameworks"):
                lines.append("Frameworks: " + ", ".join(path["frameworks"][:6]))
            for text in path.get("remove") or []:
                lines.append(f"Remove: {text}")
            for note in (path.get("notes") or [])[:2]:
                lines.append(f"Slight miss ({note['agent']}): {note['detail']}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def roles_for(node: dict, observations: list[dict]) -> set[str]:
    props = node.get("properties") or {}
    kind = node.get("kind") or ""
    name = node.get("name") or ""
    path = str(props.get("path") or "")
    table = str(props.get("table") or "")
    data_blob = " ".join([name, path, table, node.get("receives") or ""])
    themes = {item.get("theme") for item in observations}
    roles: set[str] = set()
    if kind == "endpoint" and not props.get("auth"):
        roles.update({"PUBLIC_ENDPOINT", "PUBLIC_API", "INTERNET", "APPLICATION", "API", "USER"})
    elif kind == "endpoint":
        roles.update({"AUTHENTICATED_API", "APPLICATION", "API", "USER"})
    if kind == "trigger" and props.get("untrusted"):
        roles.update({"INTERNET", "UNTRUSTED_TRIGGER", "USER", "SOURCE_CODE"})
    elif kind == "trigger":
        roles.update({"USER", "SOURCE_CODE"})
    if kind == "exposure":
        roles.update({"INTERNET", "PUBLIC_STORAGE", "STORAGE"})
    if kind == "function":
        roles.update({"APPLICATION", "API", "SERVICE"})
    if kind in {"container", "workload"}:
        roles.update({"CONTAINER", "SERVICE", "APPLICATION", "PRODUCTION"})
    if kind == "workflow":
        roles.update({"SOURCE_CODE", "APPLICATION"})
    if kind == "dependency":
        roles.add("SOURCE_CODE")
    if kind == "datastore":
        roles.add("DATABASE")
        if props.get("sensitive") or PII_WORDS.search(data_blob):
            roles.add("PII_DATABASE")
        if PCI_WORDS.search(data_blob):
            roles.update({"PCI_DATA", "PAYMENT_DB", "FINANCIAL_DATA"})
        if MONEY_WORDS.search(data_blob):
            roles.update({"FINANCIAL_DATA", "PAYMENT_DB"})
    if kind == "bucket":
        roles.add("STORAGE")
        if props.get("public"):
            roles.update({"INTERNET", "PUBLIC_STORAGE"})
        if props.get("sensitive") or MONEY_WORDS.search(data_blob):
            roles.update({"FINANCIAL_DATA", "PAYMENT_DB"})
        if PII_WORDS.search(name + " " + table):
            roles.add("PII_DATABASE")
    if kind == "secret" or "credential" in themes or (SECRET_WORDS.search(name) and kind in {"secret", "cloud"}):
        roles.add("SECRET")
    if props.get("wildcard") or "iam" in themes:
        roles.update({"IAM_ROLE", "IAM_ADMIN", "ADMIN_POLICY"})
    if kind == "secret" and "role" in name.lower():
        roles.add("IAM_ROLE")
    if themes & {"ai_tool", "model_load", "rag", "agency"}:
        roles.add("AI_TOOL")
    if ADMIN_WORDS.search(name) and kind in {"function", "endpoint"}:
        roles.add("ADMIN_FUNCTION")
    if any(item.get("privilege") == "admin" for item in observations):
        roles.add("ADMIN_FUNCTION")
    if MONEY_WORDS.search(path or name) and kind in {"endpoint", "function"}:
        roles.add("PAYMENT_API")
    if props.get("privileged"):
        roles.add("PRIVILEGED")
    if BACKUP_WORDS.search(name):
        roles.update({"BACKUP", "STORAGE"})
    if DEBUG_WORDS.search(path or name) and kind in {"endpoint", "function"}:
        roles.add("DEBUG_SURFACE")
    return roles


def controls_for(node: dict, observations: list[dict]) -> set[str]:
    props = node.get("properties") or {}
    found: set[str] = set()
    if props.get("auth") is True:
        found.update({"AUTHORIZATION_CHECK", "AUTHENTICATION"})
    if props.get("mfa") is True:
        found.add("MFA")
    blob = " ".join((item.get("evidence") or "") + " " + (item.get("title") or "") for item in observations).lower()
    if re.search(r"\b(mfa|totp|webauthn)\b", blob) and "no mfa" not in blob and "without mfa" not in blob:
        found.add("MFA")
    return found


FRAMEWORKS = (
    {"id": "owasp-top10-2021", "name": "OWASP Top 10", "focus": "Broken access control, injection, misconfiguration, SSRF, vulnerable components"},
    {"id": "owasp-api-2023", "name": "OWASP API Security Top 10", "focus": "Object-level and function-level authorization, inventory, unsafe consumption"},
    {"id": "owasp-asvs", "name": "OWASP ASVS", "focus": "Authentication, session, access control, validation, stored data"},
    {"id": "owasp-cicd", "name": "OWASP CI/CD Top 10", "focus": "Untrusted triggers, secrets in jobs, unsigned deploy"},
    {"id": "owasp-llm", "name": "OWASP LLM Top 10", "focus": "Tool authority, sensitive retrieval, executable model loads"},
    {"id": "owasp-kubernetes", "name": "OWASP Kubernetes Top 10", "focus": "Privileged workloads, secrets in environment, open control plane"},
    {"id": "owasp-serverless", "name": "OWASP Serverless Top 10", "focus": "Overprivileged roles, event injection, secret in environment"},
    {"id": "owasp-docker", "name": "OWASP Docker Top 10", "focus": "Root images, privileged containers, secrets in the build"},
    {"id": "owasp-subtractive", "name": "OWASP Subtractive Hardening", "focus": "Deletion of the edge, ahead of adding another detector"},
    {"id": "stride", "name": "STRIDE", "focus": "Spoofing, tampering, repudiation, information disclosure, denial of service, elevation"},
    {"id": "dread", "name": "DREAD", "focus": "Damage, reproducibility, exploitability, affected users, discoverability as the existing score factors"},
    {"id": "pasta", "name": "PASTA", "focus": "Objective-centric simulation against the application decomposition"},
    {"id": "linddun", "name": "LINDDUN", "focus": "Linkability, identifiability, disclosure, unawareness of personal data"},
    {"id": "octave", "name": "OCTAVE", "focus": "Operational assets, the people who can reach them, and the impact"},
    {"id": "trike", "name": "Trike", "focus": "Actor, action, and asset: which role can perform which action"},
    {"id": "vast", "name": "VAST", "focus": "Application threat model and operational threat model on the same graph"},
    {"id": "attack-tree", "name": "Attack trees", "focus": "Each hunt is a tree from an entry to an objective"},
    {"id": "mitre-attack", "name": "MITRE ATT&CK", "focus": "Tactic names for the walk. No procedures."},
    {"id": "lockheed", "name": "Lockheed Martin Kill Chain", "focus": "Delivery, exploitation, and actions on the objective"},
)


def _materialize(walk, nodes, obs_by, roles, controls, hypothesis) -> dict:
    labels = []
    hops = []
    included = []
    present_controls: set[str] = set()
    for node_id in walk:
        node = nodes[node_id]
        label = node.get("receives") or node.get("name") or node_id
        if not labels or labels[-1] != label:
            labels.append(label)
        present_controls |= controls[node_id]
        hop_obs = obs_by[node_id]
        included.extend(hop_obs)
        hops.append(
            {
                "node_id": node_id,
                "label": label,
                "kind": node.get("kind"),
                "roles": sorted(roles[node_id]),
                "file": node.get("file"),
                "line": node.get("line"),
                "controls": sorted(controls[node_id]),
            }
        )
    scored = _score(walk, obs_by, roles)
    required_absent = [item for item in hypothesis["must_not_have"] if item not in present_controls and item not in {"NO_AUTHZ_CHECK", "USER_INPUT_REACHABLE"}]
    if "AUTHORIZATION_CHECK" not in present_controls and ("PUBLIC_ENDPOINT" in roles[walk[0]] or "INTERNET" in roles[walk[0]]):
        if "AUTHORIZATION_CHECK" not in required_absent:
            required_absent.append("AUTHORIZATION_CHECK")
    if "MFA" not in present_controls and "ADMIN_FUNCTION" in set().union(*(roles[node_id] for node_id in walk)):
        if "MFA" not in required_absent:
            required_absent.append("MFA")
    remove = []
    for item in included:
        text = item.get("recommendation")
        if text and text not in remove:
            remove.append(text)
    if not remove:
        remove.append(f"Delete or constrain the walk from {labels[0]} to {labels[-1]}.")
    return {
        "labels": labels,
        "hops": hops,
        "node_ids": walk,
        "missing_controls": required_absent,
        "remove": remove[:4],
        "notes": [],
        "frameworks": list(hypothesis.get("frameworks") or []),
        **scored,
    }


def _score(walk, obs_by, roles) -> dict:
    exposures, privileges, assets, exploits = set(), set(), set(), set()
    for node_id in walk:
        for item in obs_by[node_id]:
            if item.get("exposure"):
                exposures.add(item["exposure"])
            if item.get("privilege"):
                privileges.add(item["privilege"])
            if item.get("asset"):
                assets.add(item["asset"])
            if item.get("exploitability"):
                exploits.add(item["exploitability"])
        role = roles[node_id]
        if role & {"INTERNET", "PUBLIC_ENDPOINT", "PUBLIC_API"}:
            exposures.add("public")
        if "SECRET" in role:
            privileges.add("credential")
            assets.add("credential")
        if role & {"IAM_ADMIN", "ADMIN_POLICY", "ADMIN_FUNCTION"}:
            privileges.add("admin")
            assets.add("production")
        if role & {"PII_DATABASE", "PCI_DATA"}:
            privileges.add("data")
            assets.add("sensitive")
        if role & {"FINANCIAL_DATA", "PAYMENT_DB"}:
            privileges.add("data")
            assets.add("financial")
        if "PRODUCTION" in role or "PRIVILEGED" in role:
            assets.add("production")
            privileges.add("deploy")
    if not exploits:
        exploits.add("misconfiguration")
    return score_path(exposures, privileges, assets, exploits)


def _matches(node: dict, roles: set[str], tokens: list[str]) -> bool:
    if not tokens:
        return False
    name = _fold(node.get("name") or "")
    receive = _fold(node.get("receives") or "")
    for token in tokens:
        if token in roles:
            return True
        folded = _fold(token)
        if not folded:
            continue
        if folded == name or folded == receive:
            return True
        if len(folded) >= 5 and (folded in name or folded in receive):
            return True
    return False


def _fold(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _through(path, nodes, roles, through: list[str]) -> bool:
    if not through:
        return True
    cursor = 0
    for node_id in path:
        if cursor < len(through) and _matches(nodes[node_id], roles[node_id], [through[cursor]]):
            cursor += 1
    return cursor == len(through)


def _conditions(path, obs_by, roles, controls, conditions: list[str]) -> bool:
    for condition in conditions:
        if not _condition(condition, path, obs_by, roles, controls):
            return False
    return True


def _condition(condition, path, obs_by, roles, controls) -> bool:
    if condition == "NO_AUTHZ_CHECK":
        return all("AUTHORIZATION_CHECK" not in controls[node_id] for node_id in path)
    if condition == "USER_INPUT_REACHABLE":
        sinks = {"sqli", "ssrf", "schema", "rce", "logic"}
        return any(
            item.get("exploitability") == "user_controlled" or item.get("theme") in sinks
            for node_id in path
            for item in obs_by[node_id]
        )
    return any(condition in roles[node_id] or condition in controls[node_id] for node_id in path)


def _missing(path, roles, controls, required: list[str]) -> bool:
    if not required:
        return True
    present: set[str] = set()
    for node_id in path:
        present |= controls[node_id]
        present |= roles[node_id]
    return all(item not in present for item in required)


def _question(hypothesis: dict) -> str:
    start = ", ".join(hypothesis["start"])
    target = ", ".join(hypothesis["target"])
    text = f"Can an attacker get from {start} to {target}"
    if hypothesis["through"]:
        text += " through " + " then ".join(hypothesis["through"])
    if hypothesis["must_not_have"]:
        text += " without " + ", ".join(hypothesis["must_not_have"])
    return text + "?"


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, str):
        parts = [part.strip() for part in value.split(",")]
        return [part for part in parts if part]
    if isinstance(value, (list, tuple)):
        return [item for item in value if item is not None and str(item).strip()]
    return [value]

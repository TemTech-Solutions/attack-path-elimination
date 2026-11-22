"""Plain finding text, and the exact edit for the line that was flagged.

The scan explains each line locally. It does not send source code to another service.
"""

from __future__ import annotations

import re
from pathlib import Path

CHECKOUT_V4 = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0"
_QUERY = re.compile(
    r"\b(?:SELECT\b.{0,80}\bFROM|INSERT\b.{0,40}\bINTO|UPDATE\b.{0,60}\bSET|DELETE\b.{0,40}\bFROM)\b",
    re.I | re.S,
)


def not_a_query(title: str, evidence: str, theme: str = "") -> str:
    """A database finding must contain a database question on the same line."""
    claims = theme == "sqli" or "query" in (title or "").lower()
    if not claims:
        return ""
    if _QUERY.search(evidence or ""):
        return ""
    if re.search(r"\b(?:execute|executemany|raw|query)\s*\(", evidence or "", re.I):
        return ""
    return "this line is ordinary text. It does not contain a database question, so it is not an attack path."


def exact_change(evidence: str, title: str, file: str = "") -> str:
    """The edit a reviewer can make on this line."""
    line = (evidence or "").strip()
    low_title = (title or "").lower()
    if not_a_query(title, line):
        return ""
    if "query" in low_title or _QUERY.search(line):
        return _sql_edit(line, file)
    if "not pinned to a commit" in low_title or re.search(r"@[A-Za-z0-9._-]+$", line):
        pinned = _action_edit(line)
        if pinned:
            return pinned
    if "secret value" in low_title or "<secret value>" in line:
        return _secret_edit(line)
    canned = _BY_TITLE.get(title or "")
    if canned:
        return canned.format(line=line)
    if line:
        return f"Delete `{line}` from this file. If the program still needs that behavior, write the fixed value in the file instead of taking it from outside."
    return "Delete this line. If the program still needs that behavior, write the fixed value in the file."


def explain_line(evidence: str, title: str, file: str = "") -> dict[str, str]:
    """One description built from this line, plus the erasure that removes the path."""
    line = (evidence or "").strip()
    kind = _kind(line, title, file)
    does, reason, effect, change, anchor = _voice(kind, line, title, file)
    return {
        "does": does,
        "reason": reason,
        "why": effect,
        "effect": effect,
        "change": change,
        "anchor": anchor,
    }


def _kind(line: str, title: str, file: str) -> str:
    low = f"{title} {line}".lower()
    if _QUERY.search(line) or "query" in (title or "").lower():
        return "sql"
    if "<secret value>" in line or re.search(r"\b(?:secret|password|api[_-]?key)\b\s*[:=]", line, re.I):
        return "secret"
    if re.search(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@", line) or "commit digest" in low or "not pinned" in low:
        return "action"
    learned = _learned(line, title, file)
    if learned.get("supported") and learned.get("label"):
        return str(learned["label"])
    return "line"


def _voice(kind: str, line: str, title: str, file: str) -> tuple[str, str, str, str, str]:
    """Return does, reason, effect, erasure, anchor. The quoted code makes each one distinct."""
    shown = f"`{line}`" if line else "this line"
    if kind == "sql":
        return _sql_voice(line, file, shown)
    if kind == "secret":
        return _secret_voice(line, shown)
    if kind == "action":
        return _action_voice(line, shown)
    token = _erasable(line)
    if token and line:
        does = f"{shown} is an attack path because it keeps `{token}`."
        reason = f"Erase `{token}`. That piece is what opens the path on this line."
        effect = f"`{token}` in {shown} stays reachable"
        change = f"Erase `{token}` from {shown}"
        return does, reason, effect, change, f"`{token}` on this line"
    name = (title or "This line").rstrip(".")
    does = f"{shown} is the attack path. {name}."
    reason = f"Erase {shown}. The path is the code itself, so deleting it removes the path."
    effect = f"{shown} remains an open step while it stays in the file"
    change = f"Erase {shown} from this file"
    return does, reason, effect, change, shown


def _sql_voice(line: str, file: str, shown: str) -> tuple[str, str, str, str, str]:
    pasted = _pasted_value(line)
    verb, table = _query_bits(line)
    question = f"{verb or 'database'} question" + (f" for {table}" if table else "")
    if not pasted:
        does = f"{shown} runs a {question} that was built as text."
        reason = "Erase the text-built question. The database call should keep a fixed question and take values beside it."
        effect = f"the {question} in {shown} can change with the text that was joined in"
        change = f"Erase the text-built question in {shown}. Leave a fixed question and pass each value beside it"
        return does, reason, effect, change, f"the {question} in {shown}"
    rewritten = _rewritten_query(line, _placeholder(file), pasted)
    does = f"{shown} builds a {question} by joining {pasted} into the question text."
    reason = f"Erase that join. {pasted} has to stay data, outside the question."
    effect = f"the {question} changes when {pasted} changes"
    if rewritten and rewritten != line:
        change = f"Erase the join of {pasted}. Change {shown} to `{rewritten}`"
    else:
        change = f"Erase {pasted} from the question in {shown}, and pass {pasted} beside the question as data"
    return does, reason, effect, change, f"the {question} that joins {pasted}"


def _secret_voice(line: str, shown: str) -> tuple[str, str, str, str, str]:
    match = re.search(r"\b([A-Za-z_][\w.]*)\s*[:=]", line)
    name = match.group(1) if match else "the secret"
    does = f"{shown} writes a secret value into {name}."
    reason = f"Erase the value. Anyone who can read the file can read {name}."
    effect = f"the secret stored for {name} can be read from the file"
    change = f"Erase the secret value in {shown}. Leave {name} to be read from the secret store, with no secret left in the file"
    return does, reason, effect, change, f"the secret written for {name}"


def _action_voice(line: str, shown: str) -> tuple[str, str, str, str, str]:
    match = re.search(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[A-Za-z0-9._-]+", line)
    ref = match.group(0) if match else line
    name, _, tag = ref.rpartition("@")
    tag = tag or "the tag"
    if ref.startswith("actions/checkout@") and not re.search(r"@[0-9a-f]{40}$", ref):
        replacement = CHECKOUT_V4
    elif name:
        replacement = f"{name}@<40-character commit> # {tag}"
    else:
        replacement = "<40-character commit>"
    does = f"{shown} runs `{ref}` from the tag {tag}. That tag can be moved, so the code that runs is not the copy reviewed here."
    reason = f"Erase `{tag}`. A 40-character commit does not move."
    effect = f"`{ref}` can run a different copy than the one reviewed for this file"
    change = f"Erase `{tag}` from `{ref}`. Leave `{replacement}` in its place"
    return does, reason, effect, change, f"the tag {tag} on {ref}"


def _query_bits(line: str) -> tuple[str, str]:
    verb = ""
    match = re.search(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", line, re.I)
    if match:
        verb = match.group(1).upper()
    table = ""
    table_match = re.search(r"\bFROM\s+([A-Za-z_][\w]*)|\bINTO\s+([A-Za-z_][\w]*)|\bUPDATE\s+([A-Za-z_][\w]*)", line, re.I)
    if table_match:
        table = next(group for group in table_match.groups() if group)
    return verb, table


def _erasable(line: str) -> str:
    patterns = (
        r"verify\s*=\s*False",
        r"InsecureSkipVerify",
        r"rejectUnauthorized\s*:\s*false",
        r"privileged:\s*true",
        r"hostNetwork:\s*true",
        r"pull_request_target",
        r"0\.0\.0\.0/0",
        r"0\.0\.0\.0",
        r"\bextractall\s*\(",
        r"\bnew\s+Function\s*\(",
        r"algorithms\s*=\s*\[[^\]]*none",
        r"DEBUG\s*=\s*True",
        r"app\.debug\s*=\s*True",
        r":latest\b",
        r"\b777\b",
        r"AllowAnonymous|permitAll|AllowAny|csrf_exempt",
    )
    for pattern in patterns:
        match = re.search(pattern, line, re.I)
        if match:
            return match.group(0)
    if "*" in line and re.search(r"action|resource|principal", line, re.I):
        return "*"
    return ""


def _learned(evidence: str, title: str, file: str) -> dict:
    try:
        from pathfinder.mlfind import describe_finding

        return describe_finding(evidence, title, file)
    except Exception:
        return {}


def _fallback_problem(title: str, line: str) -> str:
    name = (title or "This line").rstrip(".")
    if line:
        return f"{name}. The code a reviewer needs to see is `{line}`."
    return f"{name}."


def _fallback_happens(title: str) -> str:
    name = (title or "this line").rstrip(".").lower()
    return f"left as it is, {name} stays available to whoever can reach this file"


def _anchor(title: str, line: str) -> str:
    if _QUERY.search(line or ""):
        return "the database question on this line"
    if "commit" in (title or "").lower():
        return "the unpinned action on this line"
    if "secret" in (title or "").lower():
        return "the secret on this line"
    return (title or "this line").rstrip(".")


def _placeholder(file: str) -> str:
    ext = Path(file or "").suffix.lower()
    if ext == ".py":
        return "%s"
    if ext == ".go":
        return "$1"
    if ext == ".cs":
        return "@value"
    return "?"


def _sql_edit(evidence: str, file: str) -> str:
    original = evidence.strip()
    mark = _placeholder(file)
    pasted = _pasted_value(original)
    rewritten = _rewritten_query(original, mark, pasted)
    if pasted and rewritten and rewritten != original:
        return f"Erase the join of {pasted}. Change `{original}` to `{rewritten}`."
    if pasted:
        return (
            f"Take {pasted} out of the question text. "
            f"Leave the question as fixed words with `{mark}` where that value was, "
            f"and pass {pasted} as a separate argument to the database call. "
            f"The line to rewrite is `{original}`."
        )
    return (
        f"Rewrite `{original}` so the question text stays fixed and each outside value is a separate argument. "
        f"Use `{mark}` inside the question where a value used to be pasted."
    )


def _pasted_value(evidence: str) -> str:
    braces = re.findall(r"\{([^{}]+)\}", evidence)
    if braces:
        return ", ".join(braces)
    plus = re.search(
        r"""["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*\+\s*(?P<expr>[^)\n;]+)""",
        evidence,
        re.I,
    )
    if plus:
        return plus.group("expr").strip()
    dollar = re.findall(r"\$\{([^{}]+)\}", evidence)
    if dollar:
        return ", ".join(dollar)
    return ""


def _rewritten_query(evidence: str, mark: str, pasted: str) -> str:
    if not pasted:
        return ""
    if "{" in evidence and re.search(r"\bf[\"']", evidence):
        body = re.sub(r"\{[^{}]+\}", mark, evidence)
        body = re.sub(r"\bf([\"'])", r"\1", body)
        closer = ""
        if body.rstrip().endswith(")"):
            body = body.rstrip()[:-1]
            closer = ")"
        return f"{body}, ({pasted},){closer}" if mark == "%s" else f"{body}, {pasted}{closer}"
    match = re.search(
        r"""(?P<head>.*?["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*)(?P<quote>["'])\s*\+\s*(?P<expr>[^)\n;]+)(?P<tail>\)?)""",
        evidence,
        re.I,
    )
    if not match:
        return ""
    expr = match.group("expr").strip()
    return f"{match.group('head')}{mark}{match.group('quote')}, {expr}{match.group('tail')}"


def _action_edit(evidence: str) -> str:
    line = evidence.strip()
    if not re.search(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@", line):
        return ""
    if re.search(r"@[0-9a-f]{40}$", line):
        return ""
    if line.startswith("actions/checkout@"):
        return f"Erase the tag from `{line}`. Leave `{CHECKOUT_V4}` in its place."
    name, _, ref = line.rpartition("@")
    label = ref or "the current release"
    return (
        f"Replace `{line}` with `{name}@` and the 40-character commit for {label}. "
        f"Keep the version in a comment: `{name}@<40-character commit> # {label}`."
    )


def _secret_edit(evidence: str) -> str:
    name = "the secret"
    match = re.search(r"\b([A-Za-z_][\w.]*)\s*[:=]", evidence or "")
    if match:
        name = match.group(1)
    return (
        f"Delete the secret value from {name} on this line. "
        f"Read {name} from the secret store when the program runs. "
        f"Leave the line as `{name}=<from the secret store>` with no secret written in the file."
    )


_BY_TITLE = {
    "Untrusted pull request can enter this workflow": "Remove `pull_request_target` from the `on:` list in this workflow. The line to change shows `{line}`.",
    "Pipeline materializes a long-lived secret": "Stop writing `{line}` into a file or a shell variable. Let the runner read that secret only inside the step that needs it.",
    "Workflow script interpolates untrusted event data": "Delete `{line}` from the `run:` script. Pass the event field to a fixed command as data, not as part of the script text.",
    "Untrusted trigger can deploy": "Remove the deploy command from the job that a pull request can start. The line to remove is `{line}`.",
    "Workload image is not pinned": "Replace the image tag in `{line}` with the image digest, `image@sha256:<64 hex characters>`.",
    "Image tracks a floating latest tag": "Replace `:latest` in `{line}` with a digest: `image@sha256:<64 hex characters>`.",
    "Image build receives a secret as a build argument": "Delete the `ARG` for the secret in `{line}`. Mount the secret at build time, or read it when the container starts.",
    "Image bakes a static secret into the environment": "Delete the secret from the `ENV` line `{line}`. Read it from the secret store when the container starts.",
    "Workload runs privileged": "Delete `privileged: true` from `{line}`.",
    "Workload shares the host network": "Delete `hostNetwork: true` from `{line}`.",
    "Object storage allows public reads": "Remove the public-read grant from `{line}`.",
    "IAM policy allows every action on every resource": "Replace `*` in `{line}` with the one action and the one resource this workload uses.",
    "Python dependencies are not pinned": "Pin each requirement in `{line}` to `name==version`.",
    "npm dependencies are not pinned to an exact version": "Replace the version range in `{line}` with an exact version, with no `^` or `~`.",
    "Certificate check is disabled": "Delete the setting in `{line}` that turns certificate checks off.",
    "Wildcard cross-origin policy": "Replace `*` in `{line}` with the one site name this service is allowed to answer.",
    "Service listens on every interface": "Replace `0.0.0.0` in `{line}` with the one address this service should listen on.",
    "World-writable file mode": "Replace `777` in `{line}` with the mode for the account that runs the service.",
    "Debug switch left on": "Delete the debug switch in `{line}`.",
    "Redirect target is taken from the request": "Delete the request value from the redirect in `{line}`. Write the allowed destinations in the file.",
    "File path is built from request data": "Delete the request value from the file path in `{line}`. Open a file whose path is written in full in this file.",
    "Caller-controlled markup is written into the page": "Stop writing the caller’s text as HTML. In `{line}`, put that text in a text node.",
    "Code is built with the Function constructor": "Delete `new Function` from `{line}`. Keep the value as data.",
    "Archive is extracted without a path limit": "Delete `extractall` from `{line}`. Extract only names that stay inside one directory written in this file.",
    "Token signature check is turned off": "Delete `verify=False` or the `none` algorithm from `{line}`. Accept one named algorithm and check the signature.",
    "Anonymous authorization exception": "Delete the anonymous exception in `{line}` on any route that touches privileged data.",
    "Route without an auth check": "Add a role check before `{line}` runs, or delete the route if the application does not need it.",
    "Unauthenticated route": "Add a role check before `{line}` runs, or delete the route if the application does not need it.",
    "Dynamic execution primitive": "Delete the call that runs outside text in `{line}`. Keep that text as data.",
    "Outbound request is built from a variable": "Write the allowed host in the file and stop passing the outside address in `{line}`.",
    "Outbound request is built from caller-controlled input": "Write the allowed host in the file and stop passing the outside address in `{line}`.",
}
_SAY = {
    "Query is built from a string": (
        "This line builds a database question by pasting a value into the question text. The database can treat that value as part of the command.",
        "a person who can change the pasted value can change what the database is asked to do",
    ),
    "Query text is concatenated with caller-controlled input": (
        "This line builds a database question by pasting a value into the question text. The database can treat that value as part of the command.",
        "a person who can change the pasted value can change what the database is asked to do",
    ),
    "Third-party action is not pinned to a commit digest": (
        "This line runs another project’s action from a tag. A tag can be moved, so the workflow can run different code than the copy that was reviewed.",
        "the workflow can run a different copy of this action than the one you reviewed",
    ),
    "Secret value assigned in source": (
        "This line writes a secret value into the file. Anyone who can read the file can read the secret.",
        "the secret can be read from the file",
    ),
    "Dynamic execution primitive": (
        "This line runs text as a command. The person who supplies the text chooses what runs.",
        "the call runs whatever text it was given",
    ),
    "Certificate check is disabled": (
        "This line turns off the check that confirms the other computer’s certificate.",
        "the program will talk to a computer it did not verify",
    ),
    "Wildcard cross-origin policy": (
        "This line lets any website call this service.",
        "a page on another site can call this service",
    ),
    "Unauthenticated route": (
        "This line publishes a route and does not check who is calling.",
        "a caller this file does not name can use the route",
    ),
    "Route without an auth check": (
        "This line publishes a route and does not check who is calling.",
        "a caller this file does not name can use the route",
    ),
}

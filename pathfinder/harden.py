"""Validate each finding against the OWASP Subtractive Hardening baseline.

This pass runs after the repository walk. A finding stays when its control id
is in the baseline, the line supports that control, and the fix is deletion or
constraint. The same pass attaches the exact edit every report will show.
"""

from __future__ import annotations

from pathfinder.baseline import RULES, rule_recommendation, rule_tier, rule_title
from pathfinder.plain import exact_change, not_a_query


def validate_baseline(model, say) -> dict:
    """Keep, reject, and describe findings. `say` prints one line as it happens."""
    say("Validating findings against the OWASP Subtractive Hardening baseline")
    kept = []
    decisions = []
    for observation in list(model.observations):
        decision = _judge(observation)
        decisions.append(decision)
        say(f"  {decision['log']}")
        if not decision["keep"]:
            continue
        observation["recommendation"] = decision["fix"]
        kept.append(observation)
    model.observations = kept
    record = {
        "checked": len(decisions),
        "kept": sum(1 for item in decisions if item["keep"]),
        "rejected": sum(1 for item in decisions if not item["keep"]),
        "decisions": decisions,
        "hierarchy": "deletion > constraint",
    }
    model.baseline_validation = record
    say(
        f"Validated {record['kept']} finding(s). Rejected {record['rejected']}. "
        "Deletion stays ahead of constraint."
    )
    return record


def _judge(observation: dict) -> dict:
    rule = str(observation.get("rule") or "")
    title = str(observation.get("title") or "")
    evidence = str(observation.get("evidence") or "")
    file_name = str(observation.get("file") or "")
    line = observation.get("line") or ""
    place = f"{file_name}:{line}" if file_name else "the graph"
    control = RULES.get(rule)
    reason = not_a_query(title, evidence, str(observation.get("theme") or ""))
    if reason:
        return _decision(False, f"Rejected {place}. {reason}", "")
    if not evidence.strip():
        return _decision(False, f"Rejected {place}. The finding has no line to validate.", "")
    if control is None:
        return _decision(
            False,
            f"Rejected {place}. {rule or 'This finding'} is not an OWASP Subtractive Hardening control.",
            "",
        )
    if rule_tier(rule) == "monitoring":
        return _decision(
            False,
            f"Rejected {place}. Monitoring is not a fix. The baseline allows deletion or constraint.",
            "",
        )
    fix = _fix(observation, rule)
    return _decision(
        True,
        f"Kept {rule} {place}. {rule_title(rule)}. Fix: {rule_tier(rule)}.",
        fix,
    )


def _fix(observation: dict, rule: str) -> str:
    evidence = str(observation.get("evidence") or "").strip()
    title = str(observation.get("title") or "")
    file_name = str(observation.get("file") or "")
    exact = exact_change(evidence, title, file_name).strip()
    generic = (not exact) or exact.startswith("Delete `") or exact.startswith("Delete this line")
    if exact and not generic:
        return exact
    try:
        from pathfinder.mlfind import describe_finding

        learned = describe_finding(evidence, title, file_name)
    except Exception:
        learned = {}
    if learned.get("supported") and learned.get("remediation"):
        return learned["remediation"]
    base = rule_recommendation(rule)
    if evidence and evidence not in base:
        return f"{base} The line to change is `{evidence}`."
    return base


def _decision(keep: bool, log: str, fix: str) -> dict:
    return {"keep": keep, "log": log, "fix": fix}

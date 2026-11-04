"""Risk = exposure × privilege gain × asset value × exploitability.

Each factor is in (0, 1]. The published score is that product on a 0–100 scale.
Higher means a more useful path for an attacker, which is what the queue should
burn down first.
"""

EXPOSURE = {
    "public": 1.0,
    "untrusted_trigger": 1.0,
    "authenticated": 0.72,
    "internal": 0.5,
}

PRIVILEGE = {
    "credential": 1.0,
    "deploy": 1.0,
    "rce": 1.0,
    "admin": 0.95,
    "exposed_data": 0.9,
    "data": 0.85,
    "ssrf": 0.8,
    "logic": 0.78,
    "none": 0.35,
}

ASSET = {
    "sensitive": 1.0,
    "credential": 1.0,
    "production": 1.0,
    "financial": 0.86,
    "internal": 0.6,
}

EXPLOITABILITY = {
    "user_controlled": 0.9,
    "missing_auth": 0.86,
    "misconfiguration": 0.82,
    "heuristic_logic": 0.7,
}

BANDS = (
    (85, "Critical"),
    (70, "High"),
    (40, "Medium"),
    (0, "Low"),
)


def band_for(score: int) -> str:
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "Low"


def score_path(exposures: set[str], privileges: set[str], assets: set[str], exploits: set[str]) -> dict:
    exposure = max((EXPOSURE[item] for item in exposures if item in EXPOSURE), default=0.4)
    privilege = max((PRIVILEGE[item] for item in privileges if item in PRIVILEGE), default=PRIVILEGE["none"])
    asset = max((ASSET[item] for item in assets if item in ASSET), default=ASSET["internal"])
    exploit = max((EXPLOITABILITY[item] for item in exploits if item in EXPLOITABILITY), default=0.55)
    # A path that stacks several independent weaknesses is easier to traverse
    # than any single factor suggests. Cap the bump so one path cannot exceed 97.
    if len([item for item in exploits if item in EXPLOITABILITY]) >= 2:
        exploit = min(0.97, exploit + 0.05)
    raw = exposure * privilege * asset * exploit
    score = int(round(raw * 100))
    return {
        "exposure": round(exposure, 2),
        "privilege": round(privilege, 2),
        "asset": round(asset, 2),
        "exploitability": round(exploit, 2),
        "score": score,
        "band": band_for(score),
        "formula": "exposure × privilege × asset × exploitability",
    }

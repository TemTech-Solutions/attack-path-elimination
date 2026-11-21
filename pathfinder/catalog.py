"""Official weakness names for the baseline rules.

Names, descriptions, and the first mitigation are the wording returned from the
current CWE definition pages and the OWASP Top 10:2021 and API Security Top 10
2023 titles. A finding still explains its own line. This record only names the
weakness that line belongs to.
"""

from __future__ import annotations


def _entry(cwe: str, name: str, rank: int | None, description: str, mitigation: str, owasp: str = "") -> dict:
    return {
        "cwe": cwe,
        "cwe_name": name,
        "cwe_rank": rank,
        "description": description,
        "mitigation": mitigation,
        "owasp": owasp,
    }


RECORDS: dict[str, dict] = {
    "CWE-79": _entry(
        "CWE-79",
        "Improper Neutralization of Input During Web Page Generation",
        1,
        "The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
        "Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.",
        "A03:2021 – Injection",
    ),
    "CWE-89": _entry(
        "CWE-89",
        "Improper Neutralization of Special Elements used in an SQL Command",
        2,
        "The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.",
        "Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid. For example, consider using persistence layers such as Hibernate or Enterprise Java Beans, which can provide significant protection against SQL injection if used properly.",
        "A03:2021 – Injection",
    ),
    "CWE-22": _entry(
        "CWE-22",
        "Improper Limitation of a Pathname to a Restricted Directory",
        6,
        "The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.",
        'Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use a list of acceptable inputs that strictly conform to specifications.',
        "A03:2021 – Injection",
    ),
    "CWE-78": _entry(
        "CWE-78",
        "Improper Neutralization of Special Elements used in an OS Command",
        9,
        "The product constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command before it is sent to a downstream component.",
        "If at all possible, use library calls rather than external processes to recreate the desired functionality.",
        "A03:2021 – Injection",
    ),
    "CWE-94": _entry(
        "CWE-94",
        "Improper Control of Generation of Code",
        10,
        "The product constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.",
        "Refactor your program so that you do not have to dynamically generate code.",
        "A03:2021 – Injection",
    ),
    "CWE-502": _entry(
        "CWE-502",
        "Deserialization of Untrusted Data",
        15,
        "The product deserializes untrusted data without sufficiently ensuring that the resulting data will be valid.",
        "If available, use the signing/sealing features of the programming language to assure that deserialized data has not been tainted.",
        "A08:2021 – Software and Data Integrity Failures",
    ),
    "CWE-863": _entry(
        "CWE-863",
        "Incorrect Authorization",
        17,
        "The product performs an authorization check when an actor attempts to access a resource or perform an action, but it does not correctly perform the check.",
        "Divide the product into anonymous, normal, privileged, and administrative areas. Reduce the attack surface by carefully mapping roles with data and functionality.",
        "A01:2021 – Broken Access Control",
    ),
    "CWE-20": _entry(
        "CWE-20",
        "Improper Input Validation",
        18,
        "The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.",
        "Consider using language-theoretic security (LangSec) techniques that characterize inputs using a formal language and build recognizers for that language.",
        "",
    ),
    "CWE-284": _entry(
        "CWE-284",
        "Improper Access Control",
        19,
        "The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.",
        "Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software.",
        "A01:2021 – Broken Access Control",
    ),
    "CWE-200": _entry(
        "CWE-200",
        "Exposure of Sensitive Information to an Unauthorized Actor",
        20,
        "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.",
        "Compartmentalize the system to have safe areas where trust boundaries can be unambiguously drawn. Do not allow sensitive data to go outside of the trust boundary.",
        "",
    ),
    "CWE-306": _entry(
        "CWE-306",
        "Missing Authentication for Critical Functionality",
        21,
        "The product does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.",
        "Divide the software into anonymous, normal, privileged, and administrative areas. Identify which of these areas require a proven user identity, and use a centralized authentication capability.",
        "A07:2021 – Identification and Authentication Failures",
    ),
    "CWE-918": _entry(
        "CWE-918",
        "Server-Side Request Forgery",
        22,
        "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
        "If there is a known list of applications, IP, hostname, and/or domains to which the product is allowed to communicate, then use allowlists to ensure that outgoing requests are restricted to these known entities.",
        "A10:2021 – Server-Side Request Forgery (SSRF)",
    ),
    "CWE-77": _entry(
        "CWE-77",
        "Improper Neutralization of Special Elements used in a Command",
        23,
        "The product constructs all or part of a command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command when it is sent to a downstream component.",
        "If at all possible, use library calls rather than external processes to recreate the desired functionality.",
        "A03:2021 – Injection",
    ),
    "CWE-770": _entry(
        "CWE-770",
        "Allocation of Resources Without Limits or Throttling",
        25,
        "The product allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated.",
        "Clearly specify the minimum and maximum expectations for capabilities, and dictate which behaviors are acceptable when resource allocation reaches limits.",
        "",
    ),
    "CWE-798": _entry(
        "CWE-798",
        "Use of Hard-coded Credentials",
        None,
        "The product contains hard-coded credentials, such as a password or cryptographic key.",
        "For outbound authentication: store passwords, keys, and other credentials outside of the code in a strongly-protected, encrypted configuration file or database that is protected from access by all outsiders, including other local users on the same system.",
        "A07:2021 – Identification and Authentication Failures",
    ),
    "CWE-269": _entry(
        "CWE-269",
        "Improper Privilege Management",
        None,
        "The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.",
        "Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software.",
        "A01:2021 – Broken Access Control",
    ),
    "CWE-522": _entry(
        "CWE-522",
        "Insufficiently Protected Credentials",
        None,
        "The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.",
        "Use an appropriate security mechanism to protect the credentials.",
        "A02:2021 – Cryptographic Failures",
    ),
    "CWE-250": _entry(
        "CWE-250",
        "Execution with Unnecessary Privileges",
        None,
        "The product performs an operation at a privilege level that is higher than the minimum level required, which creates new weaknesses or amplifies the consequences of other weaknesses.",
        "Run your code using the lowest privileges that are required to accomplish the necessary tasks. If possible, create isolated accounts with limited privileges that are only used for a single task.",
        "A05:2021 – Security Misconfiguration",
    ),
    "CWE-561": _entry(
        "CWE-561",
        "Dead Code",
        None,
        "The product contains dead code, which can never be executed.",
        "Remove dead code before deploying the application.",
        "",
    ),
    "CWE-1164": _entry(
        "CWE-1164",
        "Irrelevant Code",
        None,
        "The product contains code that is not essential for execution, such that removal of the code would have no impact to intended functionality or correctness.",
        "",
        "",
    ),
    "CWE-1104": _entry(
        "CWE-1104",
        "Use of Unmaintained Third Party Components",
        None,
        "The product relies on third-party components that are not actively supported or maintained by the original developer or a trusted proxy for the original developer.",
        "",
        "A06:2021 – Vulnerable and Outdated Components",
    ),
    "CWE-829": _entry(
        "CWE-829",
        "Inclusion of Functionality from Untrusted Control Sphere",
        None,
        "The product imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.",
        "Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.",
        "A08:2021 – Software and Data Integrity Failures",
    ),
    "CWE-494": _entry(
        "CWE-494",
        "Download of Code Without Integrity Check",
        None,
        "The product downloads source code or an executable from a remote location and executes the code without sufficiently verifying the origin and integrity of the code.",
        "Perform proper forward and reverse DNS lookups to detect DNS spoofing. The CWE page marks this as only a partial solution, since it will not prevent the code from being modified on the hosting site or in transit.",
        "A08:2021 – Software and Data Integrity Failures",
    ),
    "API9": _entry("", "", None, "", "", "API9:2023 - Improper Inventory Management"),
    "API5": _entry("", "", None, "", "", "API5:2023 - Broken Function Level Authorization"),
    "A05": _entry("", "", None, "", "", "A05:2021 – Security Misconfiguration"),
}

RULES: dict[str, str] = {
    "APP01": "API9",
    "APP02": "CWE-20",
    "APP03": "CWE-798",
    "APP04": "CWE-284",
    "APP05": "CWE-94",
    "APP06": "CWE-250",
    "APP07": "CWE-561",
    "APP08": "CWE-918",
    "APP09": "CWE-89",
    "APP10": "CWE-862",
    "C01": "CWE-798",
    "C02": "CWE-250",
    "C03": "CWE-829",
    "C04": "CWE-284",
    "C05": "CWE-77",
    "C06": "CWE-306",
    "C07": "CWE-200",
    "C08": "CWE-284",
    "C09": "CWE-829",
    "C10": "CWE-494",
    "S01": "CWE-918",
    "S02": "CWE-284",
    "S03": "CWE-284",
    "S04": "CWE-284",
    "S05": "CWE-284",
    "S06": "CWE-284",
    "S07": "CWE-798",
    "S08": "CWE-200",
    "S10": "CWE-284",
    "D01": "CWE-78",
    "D02": "CWE-284",
    "D03": "CWE-269",
    "D04": "CWE-284",
    "D05": "CWE-89",
    "D06": "CWE-284",
    "D07": "CWE-269",
    "D08": "CWE-918",
    "D09": "CWE-200",
    "D10": "CWE-200",
    "A01": "CWE-829",
    "A02": "CWE-502",
    "A03": "CWE-1104",
    "A04": "CWE-250",
    "A05": "CWE-284",
    "A06": "CWE-798",
    "A07": "CWE-862",
    "A08": "CWE-918",
    "A09": "CWE-770",
    "A10": "CWE-770",
    "U01": "CWE-284",
    "U02": "CWE-798",
    "U03": "CWE-306",
    "U04": "CWE-918",
    "U05": "A05",
    "U06": "CWE-284",
    "U07": "CWE-284",
    "U08": "CWE-284",
    "U09": "CWE-494",
    "U10": "API9",
}

# APP10 is authorization. The record key CWE-862 is not in RECORDS yet — add it.
RECORDS["CWE-862"] = _entry(
    "CWE-862",
    "Missing Authorization",
    4,
    "The product does not perform an authorization check when an actor attempts to access a resource or perform an action.",
    "Divide the product into anonymous, normal, privileged, and administrative areas. Reduce the attack surface by carefully mapping roles with data and functionality.",
    "A01:2021 – Broken Access Control. API5:2023 - Broken Function Level Authorization",
)

BAND_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
_SHELL = ("system(", "popen", "shell_exec", "subprocess", "processbuilder", "runtime.getruntime", "shell=true", "exec.command", "os.system")
_CODE = ("eval(", "scriptengine", "exec(")
_DESER = ("pickle", "unserialize", "readobject", "objectinputstream", "yaml.load")
_SSRF = ("169.254.169.254", "requests.", "fetch(", "openstream", "axios", "httpx.", "curl_exec", "resttemplate", "webclient", "new url")
_XSS = ("innerhtml", "dangerouslysetinnerhtml", "document.write")
_PATH = ("../", "filepath.join", "os.path.join", "path traversal")


def present(entry: dict) -> str:
    """One attributed sentence a report can show beside the line-specific text."""
    if not entry:
        return ""
    bits = []
    if entry.get("cwe"):
        bits.append(f"{entry['cwe']} {entry.get('cwe_name') or ''}".strip())
        if entry.get("cwe_rank"):
            bits.append(f"2025 CWE Top 25 rank {entry['cwe_rank']}")
        else:
            bits.append("not on the 2025 CWE Top 25")
    if entry.get("owasp"):
        bits.append(f"OWASP {entry['owasp']}")
    if entry.get("description"):
        bits.append(f"Official description: {entry['description']}")
    if entry.get("mitigation"):
        bits.append(f"Official mitigation: {entry['mitigation']}")
    return ". ".join(bits) + ("." if bits else "")


def match(rule: str, evidence: str = "") -> dict:
    """Pick the weakness that fits this rule and, when the line is more specific, this evidence."""
    low = (evidence or "").lower()
    key = _by_evidence(low) or RULES.get((rule or "").upper())
    if (rule or "").upper() == "APP07" and _package_evidence(low):
        key = "CWE-1104"
    if not key or key not in RECORDS:
        return {}
    found = dict(RECORDS[key])
    found["database"] = present(found)
    return found


def _package_evidence(low: str) -> bool:
    return any(token in low for token in ("requirements", "package.json", "go.mod", "gemfile", "unpinned", "dependency"))


def _by_evidence(low: str) -> str:
    if not low:
        return ""
    if any(token in low for token in _XSS):
        return "CWE-79"
    if any(token in low for token in _DESER):
        return "CWE-502"
    if any(token in low for token in _SHELL):
        return "CWE-78"
    if any(token in low for token in _CODE):
        return "CWE-94"
    if any(token in low for token in ("select ", "insert ", "update ", "delete ", "union ")):
        return "CWE-89"
    if any(token in low for token in _SSRF):
        return "CWE-918"
    if any(token in low for token in _PATH):
        return "CWE-22"
    return ""


def rank_value(item: dict | None) -> int:
    rank = (item or {}).get("cwe_rank")
    return rank if isinstance(rank, int) and rank > 0 else 100


def annotate_path(path: dict) -> dict:
    """Remember the highest-priority 2025 CWE rank on this walk."""
    best_rank = 100
    best: dict | None = None
    for hop in list(path.get("hops") or []) + list(path.get("findings") or []):
        info = hop if hop.get("cwe") else match(str(hop.get("rule") or ""), str(hop.get("evidence") or ""))
        rank = rank_value(info)
        if rank < best_rank:
            best_rank = rank
            best = info
    if best and best_rank < 100:
        path["cwe"] = best.get("cwe")
        path["cwe_name"] = best.get("cwe_name")
        path["cwe_rank"] = best_rank
    else:
        path["cwe_rank"] = None
    return path


def path_key(path: dict) -> tuple:
    annotate_path(path)
    return (BAND_ORDER.get(path.get("band") or "", 4), rank_value(path), -(path.get("score") or 0), path.get("category") or "")


def finding_key(item: dict) -> tuple:
    return (BAND_ORDER.get(item.get("band") or "", 4), rank_value(item), -(item.get("score") or 0))

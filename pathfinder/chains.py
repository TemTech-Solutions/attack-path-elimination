"""Compose reachable edges into attacker stories.

A scanner would emit the missing auth check, the outbound fetch, the metadata
read, and the bucket as four tickets. This module keeps them on one path when
the call graph actually connects them.
"""

from __future__ import annotations

import hashlib

from pathfinder.baseline import TIER_RANK, rule_family, rule_tier
from pathfinder.model import RepoModel
from pathfinder.scoring import score_path

STORIES = [
    {
        "category": "cloud_escalation",
        "entry_kinds": {"endpoint"},
        "requires": ("ssrf", "credential"),
        "include": {"unauthenticated", "authz", "ssrf", "metadata", "credential", "bucket"},
        "crowns": {"metadata", "credential", "bucket", "ssrf"},
        "cloud": True,
    },
    {
        "category": "injection",
        "entry_kinds": {"endpoint"},
        "requires": ("sqli",),
        "include": {"unauthenticated", "sqli", "database"},
        "crowns": {"sqli", "database"},
        "cloud": False,
    },
    {
        "category": "business_logic",
        "entry_kinds": {"endpoint"},
        "requires": ("logic",),
        "include": {"unauthenticated", "authz", "logic"},
        "crowns": {"logic"},
        "cloud": False,
    },
    {
        "category": "remote_execution",
        "entry_kinds": {"endpoint"},
        "requires": ("rce",),
        "include": {"unauthenticated", "authz", "rce"},
        "crowns": {"rce"},
        "cloud": False,
    },
    {
        "category": "exploit_primitive",
        "entry_kinds": {"endpoint"},
        "requires": ("ssrf",),
        "forbid": {"credential"},
        "include": {"unauthenticated", "ssrf"},
        "crowns": {"ssrf"},
        "cloud": False,
    },
    {
        "category": "supply_chain",
        "entry_kinds": {"trigger"},
        "requires": ("deploy",),
        "include": {"trigger", "action", "dependency", "pipeline_input", "credential", "container", "deploy", "provenance", "pipeline_def"},
        "crowns": {"credential", "deploy", "container"},
        "cloud": False,
    },
    {
        "category": "data_exposure",
        "entry_kinds": {"exposure"},
        "requires": ("bucket",),
        "include": {"public_bucket", "bucket"},
        "crowns": {"bucket"},
        "cloud": False,
    },
    {
        "category": "network_exposure",
        "entry_kinds": {"exposure"},
        "requires": ("open_network",),
        "include": {"open_network"},
        "crowns": {"open_network"},
        "cloud": True,
    },
    {
        "category": "privilege_expansion",
        "entry_kinds": {"cloud"},
        "requires": ("iam",),
        "include": {"iam"},
        "crowns": {"iam"},
        "cloud": True,
    },
    {
        "category": "ai_agency",
        "entry_kinds": {"endpoint", "workload"},
        "requires": ("ai_tool",),
        "include": {"unauthenticated", "authz", "ai_tool", "agency", "rag"},
        "crowns": {"ai_tool"},
        "cloud": False,
    },
    {
        "category": "model_execution",
        "entry_kinds": {"endpoint", "workload"},
        "requires": ("model_load",),
        "include": {"model_load", "unauthenticated"},
        "crowns": {"model_load"},
        "cloud": False,
    },
]


def build_paths(model: RepoModel) -> list[dict]:
    graph = model.children()
    cache: dict[str, set[str]] = {}

    def reachable(start: str) -> set[str]:
        cached = cache.get(start)
        if cached is not None:
            return cached
        seen: set[str] = set()
        stack = [start]
        while stack:
            current = stack.pop()
            if current in seen or current not in model.nodes:
                continue
            seen.add(current)
            stack.extend(graph.get(current, []))
        cache[start] = seen
        return seen

    paths = []
    seen_signatures = set()
    for entry_id in _entries(model):
        reached = reachable(entry_id)
        depth = _depths(graph, entry_id)
        observations = [item for item in model.observations if item.get("node_id") in reached]
        themes = _themes(model, reached, observations)
        for spec in STORIES:
            entry = model.nodes[entry_id]
            if entry["kind"] not in spec["entry_kinds"]:
                continue
            if any(theme not in themes for theme in spec["requires"]):
                continue
            if any(theme in themes for theme in spec.get("forbid", ())):
                continue
            path = _story(model, entry_id, reached, observations, depth, reachable, spec)
            if path is None:
                continue
            signature = (path["category"], path["narrative"])
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)
            paths.append(path)
    layered = _layered(paths)
    if layered is not None:
        paths.append(layered)
    paths.sort(key=lambda item: (-item["score"], item["category"]))
    return paths[:40]


def _story(model, entry_id, reached, observations, depth, reachable, spec) -> dict | None:
    included = [item for item in observations if item.get("theme") in spec["include"]]
    themes = _themes(model, reached, included)
    crowns = [node_id for node_id in reached if _node_theme(model.nodes[node_id]) in spec["crowns"] or _obs_theme(observations, node_id) in spec["crowns"]]
    pivot = _pivot(model, reached, crowns, depth, reachable, entry_id)
    labels, hops = _labels(model, entry_id, included, themes, pivot, spec)
    if len(labels) < 2:
        return None
    narrative = "An attacker can move from " + " → ".join(labels) + "."
    exposures, privileges, assets, exploits = _factors(model, entry_id, included, themes, spec)
    scored = score_path(exposures, privileges, assets, exploits)
    identity = any(item.get("identity") for item in included) or "authz" in themes
    digest = hashlib.sha1(f"{spec['category']}|{narrative}".encode()).hexdigest()[:12]
    recommendations = []
    for hop in sorted(hops, key=lambda item: TIER_RANK.get(item.get("tier") or "deletion", 0)):
        text = hop.get("recommendation")
        if text and text not in recommendations:
            tier = (hop.get("tier") or "deletion").capitalize()
            recommendations.append(f"{tier}: {text}")
    return {
        "id": digest,
        "category": spec["category"],
        "narrative": narrative,
        "labels": labels,
        "hops": hops,
        "findings": [
            {
                "rule": item.get("rule"),
                "title": item.get("title"),
                "file": item.get("file"),
                "line": item.get("line"),
                "evidence": item.get("evidence"),
                "recommendation": item.get("recommendation"),
            }
            for item in included
        ],
        "node_ids": [hop["node_id"] for hop in hops if hop.get("node_id")],
        "flags": {
            "identity": identity,
            "cloud": bool(spec.get("cloud")),
            "supply_chain": spec["category"] == "supply_chain",
            "business_logic": spec["category"] == "business_logic",
            "ai": spec["category"] in {"ai_agency", "model_execution"},
        },
        "recommendations": recommendations,
        **scored,
    }


def _labels(model, entry_id, included, themes, pivot, spec):
    entry = model.nodes[entry_id]
    labels = []
    hops = []

    def add(label, node_id, *, rule="", evidence="", recommendation="", file=None, line=None):
        if not label or label in labels:
            return
        node = model.nodes.get(node_id) or {}
        labels.append(label)
        hops.append(
            {
                "label": label,
                "node_id": node_id,
                "rule": rule,
                "file": file if file is not None else node.get("file"),
                "line": line if line is not None else node.get("line"),
                "evidence": evidence,
                "recommendation": recommendation,
                "tier": rule_tier(rule) if rule else "",
                "family": rule_family(rule) if rule else "",
            }
        )

    add(_entry_label(entry), entry_id, evidence=entry.get("name") or "")
    auth = _first(included, {"authz", "unauthenticated"})
    if auth and spec["category"] != "supply_chain":
        add(
            "Auth bypass",
            auth.get("node_id"),
            rule=auth.get("rule", ""),
            evidence=auth.get("evidence", ""),
            recommendation=auth.get("recommendation", ""),
            file=auth.get("file"),
            line=auth.get("line"),
        )
    exploit = _first(included, {"ssrf", "sqli", "logic", "rce"})
    if pivot and (not exploit or pivot != exploit.get("node_id")) and spec["category"] not in {"supply_chain", "data_exposure"}:
        pivot_node = model.nodes[pivot]
        stem = (pivot_node.get("file") or "service").rsplit("/", 1)[-1].rsplit(".", 1)[0]
        add(f"Internal service {stem}.{pivot_node['name']}", pivot, evidence=pivot_node.get("receives") or pivot_node["name"])
    if "ssrf" in themes and spec["category"] in {"cloud_escalation", "exploit_primitive"}:
        obs = _first(included, {"ssrf"})
        add("SSRF", obs.get("node_id") if obs else pivot, rule=(obs or {}).get("rule", "APP08"), evidence=(obs or {}).get("evidence", ""), recommendation=(obs or {}).get("recommendation", ""), file=(obs or {}).get("file"), line=(obs or {}).get("line"))
    if "sqli" in themes and spec["category"] == "injection":
        obs = _first(included, {"sqli"})
        add("Query injection", obs.get("node_id") if obs else None, rule=(obs or {}).get("rule", "APP09"), evidence=(obs or {}).get("evidence", ""), recommendation=(obs or {}).get("recommendation", ""), file=(obs or {}).get("file"), line=(obs or {}).get("line"))
    if "logic" in themes and spec["category"] == "business_logic":
        obs = _first(included, {"logic"})
        add((obs or {}).get("title") or "Unbounded business action", obs.get("node_id") if obs else None, rule=(obs or {}).get("rule", "APP10"), evidence=(obs or {}).get("evidence", ""), recommendation=(obs or {}).get("recommendation", ""), file=(obs or {}).get("file"), line=(obs or {}).get("line"))
    if "rce" in themes and spec["category"] == "remote_execution":
        obs = _first(included, {"rce"})
        add("Dynamic execution", obs.get("node_id") if obs else None, rule=(obs or {}).get("rule", "APP05"), evidence=(obs or {}).get("evidence", ""), recommendation=(obs or {}).get("recommendation", ""), file=(obs or {}).get("file"), line=(obs or {}).get("line"))
    if "metadata" in themes and spec["category"] == "cloud_escalation":
        node_id = _node_by_kind(model, reached_ids=None, kind="cloud", name="Instance metadata service")
        add("Metadata service", node_id, rule="APP08", recommendation="Remove workload network access to the instance metadata service.")
    if spec["category"] == "cloud_escalation" and "credential" in themes:
        node_id = _node_by_kind(model, reached_ids=None, kind="secret", name="Cloud role credentials")
        add("Cloud role credentials", node_id, rule="APP03", recommendation="Remove static cloud credentials from the workload. The instance role should not be readable by application code.")
    if spec["category"] == "supply_chain":
        action = _first(included, {"action"})
        if action:
            add("Unpinned GitHub Action", action.get("node_id"), rule=action.get("rule", ""), evidence=action.get("evidence", ""), recommendation=action.get("recommendation", ""), file=action.get("file"), line=action.get("line"))
        if "dependency" in themes:
            dep = _first_node(model, "dependency")
            obs = _first(included, {"dependency"})
            add("Unpinned dependencies", dep or (obs or {}).get("node_id"), rule=(obs or {}).get("rule", "APP07"), evidence=(obs or {}).get("evidence", ""), recommendation=(obs or {}).get("recommendation", ""))
        secret = _preferred_secret(model)
        if secret:
            add(secret["name"], secret["id"], rule="C01", recommendation="Remove production secrets from workflows an untrusted change can trigger.")
        if "container" in themes:
            container = _first_node(model, "container")
            add("Container build", container, rule="APP06")
        workload = _first_node(model, "workload")
        if workload:
            name = model.nodes[workload]["name"]
            privileged = model.nodes[workload]["properties"].get("privileged")
            label = f"Production workload {name}" + (" (privileged)" if privileged else "")
            add(label, workload, rule="C02" if privileged else "C08", recommendation="Remove the direct deploy edge from the untrusted trigger, and drop privileged execution.")
        if "provenance" in themes:
            obs = _first(included, {"provenance"})
            add("Unsigned artifact", (obs or {}).get("node_id"), rule=(obs or {}).get("rule", "C10"), evidence=(obs or {}).get("evidence", ""), recommendation=(obs or {}).get("recommendation", ""), file=(obs or {}).get("file"), line=(obs or {}).get("line"))
    if "bucket" in themes and spec["category"] in {"cloud_escalation", "data_exposure"}:
        bucket = _bucket(model)
        if bucket:
            add(f"S3 bucket {bucket['name']}", bucket["id"], rule="APP08" if spec["category"] == "cloud_escalation" else "APP01")
            if bucket["properties"].get("sensitive"):
                add("Sensitive data", bucket["id"], rule="APP08" if spec["category"] == "cloud_escalation" else "APP01", recommendation="Delete public and overly broad access to the classified bucket.")
    if spec["category"] == "injection":
        store = _first_node(model, "datastore")
        if store:
            add(model.nodes[store]["name"], store, rule="APP09")
    if spec["category"] == "network_exposure":
        obs = _first(included, {"open_network"})
        add("Open administrative path", (obs or {}).get("node_id") or entry_id, rule=(obs or {}).get("rule", "S04"), evidence=(obs or {}).get("evidence", ""), recommendation=(obs or {}).get("recommendation", ""), file=(obs or {}).get("file"), line=(obs or {}).get("line"))
    if spec["category"] == "privilege_expansion":
        obs = _first(included, {"iam"})
        add("Every action on every resource", (obs or {}).get("node_id") or entry_id, rule=(obs or {}).get("rule", "S02"), evidence=(obs or {}).get("evidence", ""), recommendation=(obs or {}).get("recommendation", ""), file=(obs or {}).get("file"), line=(obs or {}).get("line"))
    if spec["category"] == "ai_agency":
        obs = _first(included, {"ai_tool"})
        add("Overprivileged agent tool", (obs or {}).get("node_id"), rule=(obs or {}).get("rule", "A04"), evidence=(obs or {}).get("evidence", ""), recommendation=(obs or {}).get("recommendation", ""), file=(obs or {}).get("file"), line=(obs or {}).get("line"))
    if spec["category"] == "model_execution":
        obs = _first(included, {"model_load"})
        add("Executable model load", (obs or {}).get("node_id"), rule=(obs or {}).get("rule", "A02"), evidence=(obs or {}).get("evidence", ""), recommendation=(obs or {}).get("recommendation", ""), file=(obs or {}).get("file"), line=(obs or {}).get("line"))
    return labels, hops


def _factors(model, entry_id, included, themes, spec):
    entry = model.nodes[entry_id]
    exposures = { _entry_exposure(entry) }
    privileges, assets, exploits = set(), set(), set()
    for item in included:
        if item.get("privilege"):
            privileges.add(item["privilege"])
        if item.get("asset"):
            assets.add(item["asset"])
        if item.get("exploitability"):
            exploits.add(item["exploitability"])
    bucket = _bucket(model)
    if bucket and "bucket" in themes and spec["category"] in {"cloud_escalation", "data_exposure"}:
        if bucket["properties"].get("sensitive"):
            assets.add("sensitive")
        if bucket["properties"].get("public") and spec["category"] == "data_exposure":
            privileges.add("exposed_data")
            exposures.add("public")
    if spec["category"] == "supply_chain":
        privileges.add("deploy")
        assets.add("production")
    return exposures, privileges, assets, exploits


def _pivot(model, reached, crowns, depth, reachable, entry_id):
    if not crowns:
        return None
    best = None
    best_depth = -1
    handler = model.nodes[entry_id]["properties"].get("handler")
    for node_id in reached:
        node = model.nodes[node_id]
        if node["kind"] != "function":
            continue
        found = reachable(node_id)
        if not all(crown in found or crown == node_id for crown in crowns):
            continue
        if handler and node["name"] == handler and len(crowns) > 1:
            continue
        node_depth = depth.get(node_id, 0)
        if node_depth > best_depth:
            best = node_id
            best_depth = node_depth
    return best


def _entries(model: RepoModel):
    for node in model.nodes.values():
        if node["kind"] == "endpoint" and not node["properties"].get("auth"):
            yield node["id"]
        elif node["kind"] == "trigger" and node["properties"].get("untrusted"):
            yield node["id"]
        elif node["kind"] == "exposure":
            yield node["id"]
        elif node["kind"] == "cloud" and node["properties"].get("wildcard"):
            yield node["id"]
        elif node["kind"] == "workload" and node["properties"].get("ai_entry"):
            yield node["id"]


def _themes(model, reached, observations) -> set[str]:
    themes = {item.get("theme") for item in observations if item.get("theme")}
    for node_id in reached:
        virtual = _node_theme(model.nodes[node_id])
        if virtual:
            themes.add(virtual)
    return themes


def _node_theme(node: dict) -> str | None:
    kind = node["kind"]
    if kind == "cloud" and "metadata" in node["name"].lower():
        return "metadata"
    if kind == "secret":
        return "credential"
    if kind == "bucket":
        return "bucket"
    if kind == "datastore":
        return "database"
    if kind == "workload":
        return "deploy"
    if kind == "container":
        return "container"
    if kind == "dependency":
        return "dependency"
    if kind == "trigger":
        return "trigger"
    return None


def _obs_theme(observations, node_id) -> str | None:
    for item in observations:
        if item.get("node_id") == node_id:
            return item.get("theme")
    return None


def _entry_label(entry: dict) -> str:
    props = entry.get("properties") or {}
    if entry["kind"] == "endpoint":
        prefix = "Authenticated API" if props.get("auth") else "Public API"
        return f"{prefix} {props.get('method', 'GET')} {props.get('path', entry['name'])}"
    if entry["kind"] == "trigger":
        return f"Untrusted pipeline trigger {props.get('trigger', entry['name'])}"
    if entry["kind"] == "exposure":
        if props.get("open_network") and not props.get("public_storage"):
            return "Internet"
        return "Public object storage"
    if entry["kind"] == "cloud" and props.get("wildcard"):
        return "Wildcard IAM trust"
    if entry["kind"] == "workload" and props.get("ai_entry"):
        return f"AI runtime {entry['name']}"
    return entry["name"]


def _entry_exposure(entry: dict) -> str:
    if entry["kind"] == "trigger":
        return "untrusted_trigger"
    if entry["properties"].get("auth"):
        return "authenticated"
    return "public"


def _first(observations, themes: set[str]):
    for theme in themes:
        for item in observations:
            if item.get("theme") == theme:
                return item
    return None


def _first_node(model: RepoModel, kind: str):
    for node in model.nodes.values():
        if node["kind"] == kind:
            return node["id"]
    return None


def _node_by_kind(model, reached_ids, kind, name):
    for node in model.nodes.values():
        if node["kind"] == kind and node["name"] == name:
            return node["id"]
    return None


def _bucket(model: RepoModel):
    buckets = [node for node in model.nodes.values() if node["kind"] == "bucket"]
    if not buckets:
        return None
    buckets.sort(key=lambda node: (not node["properties"].get("sensitive"), node["name"]))
    return buckets[0]


def _preferred_secret(model: RepoModel):
    secrets = [node for node in model.nodes.values() if node["kind"] == "secret" and node["name"] != "Cloud role credentials"]
    if not secrets:
        return None
    secrets.sort(key=lambda node: ("AWS" not in node["name"], node["name"]))
    return secrets[0]


def _layered(paths: list[dict]) -> dict | None:
    """One sentence when a supply-chain path and an application cloud path both exist.

    The OWASP baseline treats those as one conductive stack, not two tickets.
    """
    cloud = next((path for path in paths if path["category"] == "cloud_escalation"), None)
    supply = next((path for path in paths if path["category"] == "supply_chain"), None)
    if cloud is None or supply is None:
        return None
    narrative = f"Across the stack, {supply['narrative']} {cloud['narrative']}"
    score = min(97, max(cloud["score"], supply["score"]))
    recommendations = []
    for text in list(supply["recommendations"]) + list(cloud["recommendations"]):
        if text not in recommendations:
            recommendations.append(text)
    return {
        "id": hashlib.sha1(narrative.encode()).hexdigest()[:12],
        "category": "stacked",
        "narrative": narrative,
        "labels": supply["labels"] + cloud["labels"],
        "hops": supply["hops"] + cloud["hops"],
        "findings": supply["findings"] + cloud["findings"],
        "node_ids": list(dict.fromkeys(supply["node_ids"] + cloud["node_ids"])),
        "flags": {
            "identity": cloud["flags"]["identity"] or supply["flags"]["identity"],
            "cloud": True,
            "supply_chain": True,
            "business_logic": False,
            "ai": False,
        },
        "recommendations": recommendations[:8],
        "exposure": max(cloud["exposure"], supply["exposure"]),
        "privilege": max(cloud["privilege"], supply["privilege"]),
        "asset": max(cloud["asset"], supply["asset"]),
        "exploitability": max(cloud["exploitability"], supply["exploitability"]),
        "score": score,
        "band": cloud["band"] if cloud["score"] >= supply["score"] else supply["band"],
        "formula": "stacked supply-chain path and application path",
    }


def _depths(graph, start) -> dict[str, int]:
    depths = {start: 0}
    queue = [start]
    while queue:
        current = queue.pop(0)
        for child in graph.get(current, []):
            if child not in depths:
                depths[child] = depths[current] + 1
                queue.append(child)
    return depths

"""Control catalog aligned to the OWASP Subtractive Hardening baseline.

Wording is a short engineering summary of those control IDs, not a copy of the
upstream standard. The deletion goal is the remediation this tool recommends.
Families follow the published platform standards: Application, CI/CD, AWS,
Datastore, AI, and the Universal laws. Tier follows the hierarchy
deletion > constraint > monitoring. This tool does not recommend monitoring
as the fix.
"""

from __future__ import annotations


def _rule(family: str, title: str, recommendation: str, tier: str = "deletion") -> dict[str, str]:
    return {
        "family": family,
        "title": title,
        "recommendation": recommendation,
        "tier": tier,
    }


RULES: dict[str, dict[str, str]] = {
    "APP01": _rule(
        "Application",
        "Unused route and verb erasure",
        "Remove debug, legacy, and unused routes, and drop HTTP verbs the service does not need.",
    ),
    "APP02": _rule(
        "Application",
        "Schema-enforced input boundaries",
        "Reject undeclared fields at the edge. Pass only a strict schema into the service, not the raw request object.",
        "constraint",
    ),
    "APP03": _rule(
        "Application",
        "Ambient token and persistent credential deletion",
        "Remove long-lived tokens and static credentials from application code, images, and pipeline logs.",
    ),
    "APP04": _rule(
        "Application",
        "Transitive service trust collapse",
        "Remove service-to-service calls that inherit another service's authority. Scope each hop to its own audience.",
    ),
    "APP05": _rule(
        "Application",
        "Dynamic execution edge pruning",
        "Remove eval, deserialization, and shell execution paths. Call a fixed operation instead of interpreting input.",
    ),
    "APP06": _rule(
        "Application",
        "Runtime capability minimization",
        "Remove shells, package managers, curl, and privileged runtime capabilities from the production workload.",
    ),
    "APP07": _rule(
        "Application",
        "Unused dependency and dead-code stripping",
        "Remove unused packages and pin the remaining dependency set to immutable digests.",
    ),
    "APP08": _rule(
        "Application",
        "Application egress determinism",
        "Remove request-controlled outbound fetches. Allow only declared destinations, and block metadata-service access.",
    ),
    "APP09": _rule(
        "Application",
        "Parser and query boundary constraint",
        "Remove string-built queries and commands. Use a fixed statement with bound parameters.",
        "constraint",
    ),
    "APP10": _rule(
        "Application",
        "Object, function, and workflow authority reduction",
        "Remove branches that grant privileged actions without an explicit role, ownership, and state check.",
    ),
    "C01": _rule(
        "CI/CD",
        "Secrets persistence elimination",
        "Remove pipeline steps that materialize long-lived secrets into files, images, or logs.",
    ),
    "C02": _rule(
        "CI/CD",
        "Runner and workload privilege reduction",
        "Remove privileged pods, root images, host mounts, and broadly privileged runners from the deploy path.",
    ),
    "C03": _rule(
        "CI/CD",
        "Dependency chain isolation",
        "Stop resolving packages from the public internet during the build. Use a pinned, private, hash-locked source.",
    ),
    "C04": _rule(
        "CI/CD",
        "Pipeline definition integrity",
        "Remove write permission on workflow files from untrusted jobs. Workflow changes need a separate protected review.",
        "constraint",
    ),
    "C05": _rule(
        "CI/CD",
        "Build logic injection elimination",
        "Remove untrusted pull-request fields from run scripts. Keep pipeline logic in reviewed files only.",
    ),
    "C06": _rule(
        "CI/CD",
        "Trigger path authentication",
        "Remove unauthenticated or broadly callable triggers from workflows that hold secrets or deploy.",
    ),
    "C07": _rule(
        "CI/CD",
        "Pull request context isolation",
        "Remove secrets and deploy credentials from workflows that untrusted pull requests can trigger.",
    ),
    "C08": _rule(
        "CI/CD",
        "Single-actor deployment path removal",
        "Remove the direct edge from an untrusted trigger to production. Require a separate protected deploy identity.",
    ),
    "C09": _rule(
        "CI/CD",
        "Third-party integration trust reduction",
        "Remove floating third-party actions. Pin each action to a full commit digest, or delete the action.",
    ),
    "C10": _rule(
        "CI/CD",
        "Artifact provenance enforcement",
        "Block deploy of unsigned images. Require a signature or attestation before the workload is updated.",
        "constraint",
    ),
    "S01": _rule(
        "AWS",
        "Metadata credential path erasure",
        "Remove IMDSv1. Require session tokens for metadata, or remove metadata access from the workload.",
    ),
    "S02": _rule(
        "AWS",
        "Wildcard trust elimination",
        "Remove Principal * and Action *. Grant a named principal and the operations that principal performs.",
    ),
    "S03": _rule(
        "AWS",
        "Public control plane removal",
        "Remove public API endpoints for clusters and administrative services. Keep management on a private path.",
    ),
    "S04": _rule(
        "AWS",
        "Default and open network path removal",
        "Remove 0.0.0.0/0 ingress. Delete the rule, or replace it with the specific peers that must connect.",
    ),
    "S05": _rule(
        "AWS",
        "Cross-account trust reduction",
        "Remove broad AssumeRole trust. Name the principal and require an external id on cross-account roles.",
    ),
    "S06": _rule(
        "AWS",
        "Egress determinism",
        "Remove 0.0.0.0/0 egress and host networking. Allow only the destinations the workload must reach.",
    ),
    "S07": _rule(
        "AWS",
        "Identity lifecycle erasure",
        "Remove IAM users and long-lived access keys. Use a role that exists only for the workload that needs it.",
    ),
    "S08": _rule(
        "AWS",
        "Public data plane elimination",
        "Remove public ACLs and publicly reachable databases. Keep storage and data services private.",
    ),
    "S09": _rule(
        "AWS",
        "Regional surface reduction",
        "Remove unused regions from the account. Deny resource creation outside the regions you operate.",
        "constraint",
    ),
    "S10": _rule(
        "AWS",
        "Cloud network segmentation",
        "Remove flat peering and wide east-west routes. Keep each workload on a network that cannot reach the others.",
    ),
    "D01": _rule(
        "Datastore",
        "Database-to-host execution path elimination",
        "Remove shell and external-runtime features from the database, including xp_cmdshell and equivalent extensions.",
    ),
    "D02": _rule(
        "Datastore",
        "Datastore trust relationship reduction",
        "Remove linked servers, foreign data wrappers, and other datastore-to-datastore trust that is not required.",
    ),
    "D03": _rule(
        "Datastore",
        "Service identity and privilege reduction",
        "Remove GRANT ALL and shared administrative database accounts. Split read, write, and admin identities.",
    ),
    "D04": _rule(
        "Datastore",
        "Tenant and schema boundary isolation",
        "Remove shared schemas that mix tenants. Put each tenant or domain in a boundary the query cannot cross.",
        "constraint",
    ),
    "D05": _rule(
        "Datastore",
        "Dynamic query and API execution reduction",
        "Remove string-built queries. Expose a fixed data API with bound parameters.",
    ),
    "D06": _rule(
        "Datastore",
        "Replication and federation trust reduction",
        "Remove unused replication and change-stream paths, especially ones that copy production into a lower-trust store.",
    ),
    "D07": _rule(
        "Datastore",
        "Shared data-plane write authority reduction",
        "Remove global write and bulk-delete rights from application identities.",
    ),
    "D08": _rule(
        "Datastore",
        "Datastore egress determinism",
        "Remove database-originated file export and outbound procedures. The database should not open network destinations.",
    ),
    "D09": _rule(
        "Datastore",
        "Backup and export reachability reduction",
        "Remove broad access to snapshots, dumps, and exports. A recovery identity should be the only reader.",
    ),
    "D10": _rule(
        "Datastore",
        "Metadata and discovery surface reduction",
        "Remove broad catalog and information-schema access from application identities.",
    ),
    "A01": _rule(
        "AI",
        "Training data and fine-tuning pipeline erasure",
        "Remove unauthenticated or unsigned data sources from training and fine-tuning jobs.",
    ),
    "A02": _rule(
        "AI",
        "Model artifact integrity",
        "Remove pickle and other executable model loads. Load a tensor-only artifact from a trusted store.",
    ),
    "A03": _rule(
        "AI",
        "AI supply chain and plugin minimization",
        "Remove unused model hubs, plugins, and dynamically registered tools.",
    ),
    "A04": _rule(
        "AI",
        "Tool authority and privilege reduction",
        "Remove shell, network, and write tools from the agent. Keep only the read operations the task needs.",
    ),
    "A05": _rule(
        "AI",
        "Agent memory and state isolation",
        "Remove shared persistent memory across users and tenants. Keep memory inside one session.",
    ),
    "A06": _rule(
        "AI",
        "Identity and token isolation",
        "Remove ambient cloud and host credentials from the agent process. Issue a token scoped to one action.",
    ),
    "A07": _rule(
        "AI",
        "RAG reachability reduction",
        "Remove unrestricted vector search. Filter to documents the caller may read before retrieval.",
        "constraint",
    ),
    "A08": _rule(
        "AI",
        "Egress determinism and exfiltration path erasure",
        "Remove arbitrary outbound calls from the model runtime. Allow only declared destinations.",
    ),
    "A09": _rule(
        "AI",
        "Agency and autonomous loop constraint",
        "Remove unbounded agent loops and dynamic sub-agents. Cap iterations and require a person for irreversible tools.",
        "constraint",
    ),
    "A10": _rule(
        "AI",
        "Consumption and resource boundary erasure",
        "Remove unlimited token, time, and tool budgets. Enforce the cap outside the model.",
        "constraint",
    ),
    "U01": _rule(
        "Universal",
        "Adjacent reachability erasure",
        "Remove network and trust edges between components that do not need to call each other.",
    ),
    "U02": _rule(
        "Universal",
        "Static credential elimination",
        "Remove embedded secrets. Use a short-lived workload identity that cannot be read from the repository.",
    ),
    "U03": _rule(
        "Universal",
        "Cleartext control plane extinction",
        "Remove cleartext administrative protocols and unauthenticated management endpoints.",
    ),
    "U04": _rule(
        "Universal",
        "Unconstrained egress erasure",
        "Remove open egress, including instance metadata and arbitrary URL fetches.",
    ),
    "U05": _rule(
        "Universal",
        "Management and diagnostic surface reduction",
        "Remove debug, actuator, and admin interfaces from the deployed surface.",
    ),
    "U06": _rule(
        "Universal",
        "Cross-domain trust severing",
        "Remove trust from a lower-trust domain into production identity, data, or deploy.",
    ),
    "U07": _rule(
        "Universal",
        "Privilege surface pruning",
        "Remove wildcard IAM actions and resources. Grant only the operations the workload performs.",
    ),
    "U08": _rule(
        "Universal",
        "Implicit trust and transitive delegation elimination",
        "Remove hops that forward the caller's authority. Each service authenticates as itself.",
    ),
    "U09": _rule(
        "Universal",
        "Integrity and boot-chain verification",
        "Remove unsigned artifacts from the boot and deploy path.",
        "constraint",
    ),
    "U10": _rule(
        "Universal",
        "Dynamic discovery surface deletion",
        "Remove automatic discovery and self-registration paths that let a new peer join without review.",
    ),
}

FAMILIES = ("Application", "CI/CD", "AWS", "Datastore", "AI", "Universal")
TIER_RANK = {"deletion": 0, "constraint": 1, "monitoring": 2}


def rule(rule_id: str) -> dict[str, str]:
    return RULES.get(rule_id, {})


def rule_title(rule_id: str) -> str:
    return rule(rule_id).get("title", rule_id)


def rule_recommendation(rule_id: str) -> str:
    return rule(rule_id).get(
        "recommendation",
        "Remove the traversable edge instead of adding a detector for it.",
    )


def rule_family(rule_id: str) -> str:
    return rule(rule_id).get("family", "Universal")


def rule_tier(rule_id: str) -> str:
    return rule(rule_id).get("tier", "deletion")

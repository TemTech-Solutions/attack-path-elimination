"""Repository surfaces that are not application source: pipelines, images, Kubernetes, Terraform, OpenAPI, and dependency manifests."""

from __future__ import annotations

import json
import re

import yaml

from pathfinder.baseline import rule_recommendation
from pathfinder.model import RepoModel

SECRET_RE = re.compile(r"secrets\.([A-Za-z0-9_]+)")
AZURE_SECRET_RE = re.compile(r"\$\(([A-Z][A-Z0-9_]{2,})\)")
ACTION_RE = re.compile(r"uses:\s*['\"]?([^'\"\s]+)")
SHA_RE = re.compile(r"@[0-9a-f]{40}$")


def load_yaml(text: str):
    data = yaml.safe_load(text)
    if isinstance(data, dict) and True in data and "on" not in data:
        # PyYAML 1.1 treats the GitHub Actions key "on" as boolean true.
        data["on"] = data.pop(True)
    return data


def analyze_github_workflow(model: RepoModel, rel: str, text: str) -> None:
    try:
        data = load_yaml(text) or {}
    except yaml.YAMLError as exc:
        model.error(rel, f"workflow yaml: {exc}")
        return
    if not isinstance(data, dict):
        return
    triggers = _trigger_names(data.get("on"))
    untrusted = any(name in {"pull_request_target", "pull_request", "issue_comment", "workflow_run", "repository_dispatch", "workflow_dispatch"} for name in triggers)
    # push-only pipelines are trusted enough that a stolen secret is a finding,
    # not an untrusted entry. pull_request_target is the toxic case.
    holds_power = bool(SECRET_RE.search(text)) or bool(re.search(r"kubectl\s+apply|helm\s+upgrade|terraform\s+apply", text))
    untrusted_entry = (
        "pull_request_target" in triggers
        or ("pull_request" in triggers and bool(SECRET_RE.search(text)))
        or (any(name in {"repository_dispatch", "workflow_dispatch"} for name in triggers) and holds_power)
    )
    workflow = model.node(
        "workflow",
        rel,
        file=rel,
        line=1,
        lane="deploy",
        language="github-actions",
        unique=True,
        properties={
            "triggers": triggers,
            "untrusted": untrusted_entry,
            "docker": "docker build" in text,
            "deploy": bool(re.search(r"kubectl\s+apply|helm\s+upgrade|terraform\s+apply", text)),
            "installs": bool(re.search(r"pip install|npm install|npm ci|yarn install", text)),
        },
    )
    if untrusted_entry:
        if "pull_request_target" in triggers:
            trigger_name = "pull_request_target"
        elif "pull_request" in triggers:
            trigger_name = "pull_request"
        elif "repository_dispatch" in triggers:
            trigger_name = "repository_dispatch"
        else:
            trigger_name = "workflow_dispatch"
        trigger = model.node(
            "trigger",
            trigger_name,
            file=rel,
            line=1,
            lane="entry",
            unique=True,
            properties={"trigger": trigger_name, "untrusted": True, "workflow": rel},
        )
        model.edge(trigger, workflow, "INVOKES", file=rel, line=1, evidence=trigger_name)
        model.observe(
            rule="C07",
            theme="trigger",
            title="Untrusted pull request can enter this workflow",
            stage="entry",
            node_id=trigger,
            file=rel,
            line=1,
            evidence=trigger_name,
            recommendation=rule_recommendation("C07"),
            exposure="untrusted_trigger",
            privilege="deploy",
            asset="production",
            exploitability="misconfiguration",
            identity=False,
        )
    for secret_name in sorted(set(SECRET_RE.findall(text))):
        secret = model.node("secret", f"GitHub secret {secret_name}", lane="credential", unique=True, file=rel, properties={"store": "github"})
        model.edge(workflow, secret, "USES_SECRET", file=rel, evidence=f"secrets.{secret_name}")
        model.observe(
            rule="C01",
            theme="credential",
            title="Pipeline materializes a long-lived secret",
            stage="credential",
            node_id=secret,
            file=rel,
            line=_line_of(text, secret_name),
            evidence=f"secrets.{secret_name}",
            recommendation=rule_recommendation("C01"),
            exposure="untrusted_trigger" if untrusted_entry else "internal",
            privilege="credential",
            asset="credential",
            exploitability="misconfiguration",
            identity=False,
        )
    for action in sorted(set(ACTION_RE.findall(text))):
        if action.startswith("./") or SHA_RE.search(action):
            continue
        model.observe(
            rule="C09",
            theme="action",
            title="Third-party action is not pinned to a commit digest",
            stage="exploit",
            node_id=workflow,
            file=rel,
            line=_line_of(text, action.split("@")[0]),
            evidence=action,
            recommendation=rule_recommendation("C09"),
            exposure="untrusted_trigger" if untrusted_entry else "internal",
            privilege="deploy",
            asset="production",
            exploitability="misconfiguration",
            identity=False,
        )
    if re.search(r"github\.event\.", text):
        model.observe(
            rule="C05",
            theme="pipeline_input",
            title="Workflow script interpolates untrusted event data",
            stage="exploit",
            node_id=workflow,
            file=rel,
            line=_line_of(text, "github.event"),
            evidence="github.event",
            recommendation=rule_recommendation("C05"),
            exposure="untrusted_trigger" if untrusted_entry else "internal",
            privilege="deploy",
            asset="production",
            exploitability="user_controlled",
            identity=False,
        )
    if workflow and model.nodes[workflow]["properties"].get("deploy") and untrusted_entry:
        model.observe(
            rule="C08",
            theme="deploy",
            title="Untrusted trigger can deploy",
            stage="deploy",
            node_id=workflow,
            file=rel,
            line=1,
            evidence="deploy step in an untrusted workflow",
            recommendation=rule_recommendation("C08"),
            exposure="untrusted_trigger",
            privilege="deploy",
            asset="production",
            exploitability="misconfiguration",
            identity=False,
        )
    _workflow_controls(model, workflow, rel, text, triggers, untrusted_entry)


def analyze_gitlab(model: RepoModel, rel: str, text: str) -> None:
    try:
        data = load_yaml(text) or {}
    except yaml.YAMLError as exc:
        model.error(rel, f"gitlab yaml: {exc}")
        return
    if not isinstance(data, dict):
        return
    script = _flatten_scripts(data)
    untrusted = "merge_request_event" in text
    workflow = model.node(
        "workflow",
        rel,
        file=rel,
        line=1,
        lane="deploy",
        language="gitlab-ci",
        unique=True,
        properties={
            "untrusted": untrusted,
            "docker": "docker build" in script,
            "deploy": bool(re.search(r"kubectl\s+apply|helm\s+upgrade|terraform\s+apply", script)),
            "installs": bool(re.search(r"pip install|npm install|npm ci", script)),
        },
    )
    if untrusted:
        trigger = model.node("trigger", "merge_request", file=rel, line=1, lane="entry", unique=True, properties={"trigger": "merge_request", "untrusted": True})
        model.edge(trigger, workflow, "INVOKES", file=rel, line=1, evidence="merge_request_event")
        model.observe(
            rule="C07",
            theme="trigger",
            title="Merge request pipeline is an untrusted entry",
            stage="entry",
            node_id=trigger,
            file=rel,
            line=1,
            evidence="merge_request_event",
            recommendation=rule_recommendation("C07"),
            exposure="untrusted_trigger",
            privilege="deploy",
            asset="production",
            exploitability="misconfiguration",
            identity=False,
        )
    _secrets_and_deploy_observations(model, workflow, rel, script, untrusted)


def analyze_azure_pipeline(model: RepoModel, rel: str, text: str) -> None:
    try:
        data = load_yaml(text) or {}
    except yaml.YAMLError as exc:
        model.error(rel, f"azure pipeline yaml: {exc}")
        return
    if not isinstance(data, dict):
        return
    untrusted = "pr" in data
    workflow = model.node(
        "workflow",
        rel,
        file=rel,
        line=1,
        lane="deploy",
        language="azure-pipelines",
        unique=True,
        properties={
            "untrusted": untrusted,
            "docker": "docker build" in text,
            "deploy": bool(re.search(r"kubectl\s+apply|helm\s+upgrade|terraform\s+apply", text)),
            "installs": "pip install" in text or "npm install" in text,
        },
    )
    if untrusted:
        trigger = model.node("trigger", "azure pull request", file=rel, line=1, lane="entry", unique=True, properties={"trigger": "pr", "untrusted": True})
        model.edge(trigger, workflow, "INVOKES", file=rel, line=1, evidence="pr")
        model.observe(
            rule="C07",
            theme="trigger",
            title="Pull request pipeline is an untrusted entry",
            stage="entry",
            node_id=trigger,
            file=rel,
            line=1,
            evidence="pr",
            recommendation=rule_recommendation("C07"),
            exposure="untrusted_trigger",
            privilege="deploy",
            asset="production",
            exploitability="misconfiguration",
            identity=False,
        )
    for name in sorted(set(AZURE_SECRET_RE.findall(text))):
        secret = model.node("secret", f"Pipeline variable {name}", lane="credential", unique=True, file=rel)
        model.edge(workflow, secret, "USES_SECRET", file=rel, evidence=name)
    if model.nodes[workflow]["properties"].get("deploy") and untrusted:
        model.observe(
            rule="C08",
            theme="deploy",
            title="Untrusted trigger can deploy",
            stage="deploy",
            node_id=workflow,
            file=rel,
            line=1,
            evidence="deploy step",
            recommendation=rule_recommendation("C08"),
            exposure="untrusted_trigger",
            privilege="deploy",
            asset="production",
            exploitability="misconfiguration",
            identity=False,
        )


def analyze_kubernetes(model: RepoModel, rel: str, text: str) -> None:
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        if re.search(r"privileged:\s*true", text):
            workload = model.node("workload", rel, file=rel, line=1, lane="deploy", unique=True, properties={"privileged": True})
            _privileged(model, workload, rel)
        return
    for document in documents:
        if not isinstance(document, dict):
            continue
        kind = document.get("kind")
        if kind not in {"Deployment", "StatefulSet", "DaemonSet", "Pod", "Job", "CronJob"}:
            continue
        name = ((document.get("metadata") or {}).get("name")) or rel
        flags = _k8s_flags(document)
        workload = model.node(
            "workload",
            name,
            file=rel,
            line=1,
            lane="deploy",
            unique=True,
            properties={"privileged": flags["privileged"], "images": sorted(flags["images"]), "kind": kind},
        )
        if flags["privileged"] or flags["host_path"]:
            _privileged(model, workload, rel)
        if flags["host_network"]:
            model.observe(
                rule="S06",
                theme="open_network",
                title="Workload shares the host network",
                stage="deploy",
                node_id=workload,
                file=rel,
                line=1,
                evidence="hostNetwork",
                recommendation=rule_recommendation("S06"),
                exposure="internal",
                privilege="deploy",
                asset="production",
                exploitability="misconfiguration",
                identity=False,
            )
        if any(image.endswith(":latest") for image in flags["images"]):
            model.observe(
                rule="C10",
                theme="provenance",
                title="Workload image is not pinned",
                stage="deploy",
                node_id=workload,
                file=rel,
                line=1,
                evidence=":latest",
                recommendation=rule_recommendation("C10"),
                exposure="internal",
                privilege="deploy",
                asset="production",
                exploitability="misconfiguration",
                identity=False,
            )
        for secret_name in flags["secrets"]:
            secret = model.node("secret", f"Workload secret {secret_name}", lane="credential", unique=True, file=rel)
            model.edge(workload, secret, "USES_SECRET", file=rel, evidence=secret_name)


def analyze_docker(model: RepoModel, rel: str, text: str) -> None:
    has_user = bool(re.search(r"^USER\s+\S+", text, re.M))
    root = bool(re.search(r"^USER\s+root\b", text, re.M)) or not has_user
    image = model.node(
        "container",
        rel,
        file=rel,
        line=1,
        lane="deploy",
        unique=True,
        properties={"root": root, "curl": bool(re.search(r"\b(curl|wget)\b", text))},
    )
    if root or image and model.nodes[image]["properties"].get("curl"):
        model.observe(
            rule="APP06",
            theme="container",
            title="Image keeps a root user or a download tool",
            stage="deploy",
            node_id=image,
            file=rel,
            line=1,
            evidence="USER root" if root else "curl/wget",
            recommendation=rule_recommendation("APP06"),
            exposure="internal",
            privilege="deploy",
            asset="production",
            exploitability="misconfiguration",
            identity=False,
        )
    for match in re.finditer(r"^ARG\s+(\w*(?:SECRET|TOKEN|PASSWORD|KEY)\w*)", text, re.M | re.I):
        secret = model.node("secret", f"Image build arg {match.group(1)}", lane="credential", unique=True, file=rel)
        model.edge(image, secret, "USES_SECRET", file=rel, evidence=match.group(0))
        model.observe(
            rule="C01",
            theme="credential",
            title="Image build receives a secret as a build argument",
            stage="credential",
            node_id=secret,
            file=rel,
            line=_line_of(text, match.group(0)),
            evidence=match.group(0),
            recommendation=rule_recommendation("C01"),
            exposure="internal",
            privilege="credential",
            asset="credential",
            exploitability="misconfiguration",
            identity=False,
        )
    for match in re.finditer(r"^ENV\s+(\w*(?:SECRET|TOKEN|PASSWORD|KEY)\w*)\s+(\S+)", text, re.M | re.I):
        if match.group(2).startswith("$"):
            continue
        secret = model.node("secret", f"Image environment {match.group(1)}", lane="credential", unique=True, file=rel)
        model.edge(image, secret, "USES_SECRET", file=rel, evidence=match.group(1))
        model.observe(
            rule="U02",
            theme="credential",
            title="Image bakes a static secret into the environment",
            stage="credential",
            node_id=secret,
            file=rel,
            line=_line_of(text, match.group(0)),
            evidence=match.group(1),
            recommendation=rule_recommendation("U02"),
            exposure="internal",
            privilege="credential",
            asset="credential",
            exploitability="misconfiguration",
            identity=False,
        )
    if re.search(r"^FROM\s+\S+:latest\b", text, re.M | re.I):
        model.observe(
            rule="C10",
            theme="provenance",
            title="Image tracks a floating latest tag",
            stage="deploy",
            node_id=image,
            file=rel,
            line=_line_of(text, "FROM"),
            evidence="FROM :latest",
            recommendation=rule_recommendation("C10"),
            exposure="internal",
            privilege="deploy",
            asset="production",
            exploitability="misconfiguration",
            identity=False,
        )


def analyze_terraform(model: RepoModel, rel: str, text: str) -> None:
    public = bool(re.search(r'acl\s*=\s*"public-read"|block_public_acls\s*=\s*false', text))
    sensitive = bool(re.search(r'DataClassification\s*=\s*"sensitive"', text, re.I))
    for bucket_name in sorted(set(re.findall(r'bucket\s*=\s*"([a-z0-9][a-z0-9.-]{2,})"', text))):
        bucket = model.node(
            "bucket",
            bucket_name,
            file=rel,
            line=_line_of(text, bucket_name),
            lane="data",
            unique=True,
            properties={"provider": "s3", "public": public, "sensitive": sensitive},
        )
        if public:
            exposure = model.node(
                "exposure",
                f"Public object storage {bucket_name}",
                lane="entry",
                unique=True,
                properties={"public_storage": True},
            )
            model.edge(exposure, bucket, "ROUTES_TO", file=rel, evidence="public-read")
            model.observe(
                rule="S08",
                theme="public_bucket",
                title="Object storage allows public reads",
                stage="data",
                node_id=bucket,
                file=rel,
                line=_line_of(text, bucket_name),
                evidence=bucket_name,
                recommendation=rule_recommendation("S08"),
                exposure="public",
                privilege="exposed_data",
                asset="sensitive" if sensitive else "internal",
                exploitability="misconfiguration",
                identity=False,
            )
    if re.search(r'Action\s*=\s*"\*"', text) and re.search(r'Resource\s*=\s*"\*"', text):
        policy = model.node("cloud", "Wildcard IAM policy", lane="credential", unique=True, file=rel, properties={"wildcard": True})
        model.observe(
            rule="U07",
            theme="iam",
            title="IAM policy allows every action on every resource",
            stage="credential",
            node_id=policy,
            file=rel,
            line=_line_of(text, "Action"),
            evidence='Action = "*" Resource = "*"',
            recommendation=rule_recommendation("U07"),
            exposure="internal",
            privilege="admin",
            asset="production",
            exploitability="misconfiguration",
            identity=False,
        )
        model.observe(
            rule="S02",
            theme="iam",
            title="IAM policy allows every action on every resource",
            stage="credential",
            node_id=policy,
            file=rel,
            line=_line_of(text, "Action"),
            evidence='Action = "*" Resource = "*"',
            recommendation=rule_recommendation("S02"),
            exposure="internal",
            privilege="admin",
            asset="production",
            exploitability="misconfiguration",
            identity=False,
        )
    _terraform_network(model, rel, text)


def analyze_requirements(model: RepoModel, rel: str, text: str) -> None:
    unpinned = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        if "==" in line or "@" in line:
            continue
        name = re.split(r"[<>=\[]", line)[0].strip()
        if name:
            unpinned.append(name)
    if not unpinned:
        return
    node = model.node(
        "dependency",
        "Unpinned Python dependencies",
        file=rel,
        line=1,
        lane="exploit",
        unique=True,
        properties={"packages": unpinned[:12]},
    )
    model.observe(
        rule="APP07",
        theme="dependency",
        title="Python dependencies are not pinned",
        stage="exploit",
        node_id=node,
        file=rel,
        line=1,
        evidence=", ".join(unpinned[:8]),
        recommendation=rule_recommendation("APP07"),
        exposure="internal",
        privilege="none",
        asset="production",
        exploitability="misconfiguration",
        identity=False,
    )


def analyze_package_json(model: RepoModel, rel: str, text: str) -> None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        model.error(rel, f"package.json: {exc}")
        return
    unpinned = []
    for section in ("dependencies", "devDependencies"):
        for name, version in (data.get(section) or {}).items():
            if not re.fullmatch(r"\d+\.\d+\.\d+", str(version)):
                unpinned.append(name)
    if not unpinned:
        return
    node = model.node(
        "dependency",
        "Unpinned npm dependencies",
        file=rel,
        line=1,
        lane="exploit",
        unique=True,
        properties={"packages": unpinned[:12]},
    )
    model.observe(
        rule="APP07",
        theme="dependency",
        title="npm dependencies are not pinned to an exact version",
        stage="exploit",
        node_id=node,
        file=rel,
        line=1,
        evidence=", ".join(unpinned[:8]),
        recommendation=rule_recommendation("APP07"),
        exposure="internal",
        privilege="none",
        asset="production",
        exploitability="misconfiguration",
        identity=False,
    )


def analyze_openapi(model: RepoModel, rel: str, text: str) -> None:
    try:
        data = load_yaml(text) or {}
    except yaml.YAMLError as exc:
        model.error(rel, f"openapi: {exc}")
        return
    if not isinstance(data, dict) or "paths" not in data:
        return
    global_security = data.get("security")
    for path, item in (data.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if str(method).lower() not in {"get", "post", "put", "delete", "patch", "head"}:
                continue
            if not isinstance(operation, dict):
                continue
            security = operation.get("security", global_security)
            for node in list(model.nodes.values()):
                props = node.get("properties") or {}
                if node["kind"] == "endpoint" and props.get("path") == path and str(props.get("method", "")).upper() == method.upper():
                    props["spec"] = rel
                    props["spec_public"] = security == [] or security is None
                    spec = model.node("file", f"OpenAPI {method.upper()} {path}", file=rel, line=1, lane="entry", unique=True)
                    model.edge(spec, node["id"], "SPECIFIES", file=rel, evidence=f"{method.upper()} {path}")


def connect_runtime(model: RepoModel) -> None:
    workflows = [node for node in model.nodes.values() if node["kind"] == "workflow"]
    containers = [node for node in model.nodes.values() if node["kind"] == "container"]
    workloads = [node for node in model.nodes.values() if node["kind"] == "workload"]
    dependencies = [node for node in model.nodes.values() if node["kind"] == "dependency"]
    for workflow in workflows:
        props = workflow["properties"]
        if props.get("docker"):
            for container in containers:
                model.edge(workflow["id"], container["id"], "DEPLOYS", file=workflow.get("file"), evidence="docker build", confidence="INFERRED")
        if props.get("deploy"):
            for workload in workloads:
                model.edge(workflow["id"], workload["id"], "DEPLOYS", file=workflow.get("file"), evidence="deploy", confidence="INFERRED")
        if props.get("installs"):
            for dependency in dependencies:
                model.edge(workflow["id"], dependency["id"], "INVOKES", file=workflow.get("file"), evidence="package install", confidence="INFERRED")
    for container in containers:
        for workload in workloads:
            model.edge(container["id"], workload["id"], "DEPLOYS", file=container.get("file"), evidence="image to workload", confidence="INFERRED")
    credentials = [node for node in model.nodes.values() if node["kind"] == "secret" and node["name"] == "Cloud role credentials"]
    policies = [node for node in model.nodes.values() if node["kind"] == "cloud" and node["properties"].get("wildcard")]
    for secret in credentials:
        for policy in policies:
            model.edge(secret["id"], policy["id"], "TRUSTS", file=policy.get("file"), evidence="role credentials meet a wildcard policy", confidence="INFERRED")


def _privileged(model: RepoModel, workload: str, rel: str) -> None:
    model.observe(
        rule="C02",
        theme="deploy",
        title="Workload runs privileged",
        stage="deploy",
        node_id=workload,
        file=rel,
        line=1,
        evidence="privileged: true",
        recommendation=rule_recommendation("C02"),
        exposure="internal",
        privilege="deploy",
        asset="production",
        exploitability="misconfiguration",
        identity=False,
    )


def _secrets_and_deploy_observations(model, workflow, rel, text, untrusted) -> None:
    for secret_name in sorted(set(SECRET_RE.findall(text))):
        secret = model.node("secret", f"CI secret {secret_name}", lane="credential", unique=True, file=rel)
        model.edge(workflow, secret, "USES_SECRET", file=rel, evidence=secret_name)
    if model.nodes[workflow]["properties"].get("deploy") and untrusted:
        model.observe(
            rule="C08",
            theme="deploy",
            title="Untrusted trigger can deploy",
            stage="deploy",
            node_id=workflow,
            file=rel,
            line=1,
            evidence="deploy step",
            recommendation=rule_recommendation("C08"),
            exposure="untrusted_trigger",
            privilege="deploy",
            asset="production",
            exploitability="misconfiguration",
            identity=False,
        )


def _trigger_names(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    if isinstance(value, dict):
        return [str(key) for key in value.keys()]
    return []


def _flatten_scripts(data: dict) -> str:
    chunks = []

    def walk(value):
        if isinstance(value, dict):
            script = value.get("script")
            if isinstance(script, list):
                chunks.extend(str(item) for item in script)
            elif isinstance(script, str):
                chunks.append(script)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    return "\n".join(chunks)


def _k8s_flags(document: dict) -> dict:
    images, secrets = set(), set()
    privileged = False
    host_network = False
    host_path = False

    def walk(value):
        nonlocal privileged, host_network, host_path
        if isinstance(value, dict):
            if value.get("privileged") is True:
                privileged = True
            if value.get("hostNetwork") is True:
                host_network = True
            path = value.get("hostPath")
            if isinstance(path, dict):
                host_path = True
                if "docker.sock" in str(path.get("path", "")):
                    privileged = True
            image = value.get("image")
            if isinstance(image, str):
                images.add(image)
            ref = value.get("secretKeyRef")
            if isinstance(ref, dict) and ref.get("name"):
                secrets.add(str(ref["name"]))
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(document)
    return {"images": images, "secrets": secrets, "privileged": privileged, "host_network": host_network, "host_path": host_path}


def _line_of(text: str, needle: str) -> int:
    index = text.find(needle)
    if index < 0:
        return 1
    return text[:index].count("\n") + 1


def _workflow_controls(model: RepoModel, workflow: str, rel: str, text: str, triggers: list[str], untrusted_entry: bool) -> None:
    if not workflow:
        return
    write_permissions = bool(re.search(r"permissions:\s*write-all", text)) or bool(re.search(r"contents:\s*write", text))
    if untrusted_entry and write_permissions:
        model.observe(
            rule="C04",
            theme="pipeline_def",
            title="Untrusted job can write repository contents",
            stage="exploit",
            node_id=workflow,
            file=rel,
            line=_line_of(text, "permissions"),
            evidence="contents: write",
            recommendation=rule_recommendation("C04"),
            exposure="untrusted_trigger",
            privilege="deploy",
            asset="production",
            exploitability="misconfiguration",
            identity=False,
        )
    if model.nodes[workflow]["properties"].get("installs") and not re.search(r"require-hashes|package-lock.json|npm ci", text):
        model.observe(
            rule="C03",
            theme="dependency",
            title="Build resolves dependencies from the network",
            stage="exploit",
            node_id=workflow,
            file=rel,
            line=1,
            evidence="package install",
            recommendation=rule_recommendation("C03"),
            exposure="untrusted_trigger" if untrusted_entry else "internal",
            privilege="deploy",
            asset="production",
            exploitability="misconfiguration",
            identity=False,
        )
    if untrusted_entry and any(name in {"repository_dispatch", "workflow_dispatch"} for name in triggers):
        model.observe(
            rule="C06",
            theme="open_trigger",
            title="Callable trigger can start a privileged workflow",
            stage="entry",
            node_id=workflow,
            file=rel,
            line=1,
            evidence=", ".join(triggers),
            recommendation=rule_recommendation("C06"),
            exposure="untrusted_trigger",
            privilege="deploy",
            asset="production",
            exploitability="misconfiguration",
            identity=False,
        )
    deploys = model.nodes[workflow]["properties"].get("deploy") or model.nodes[workflow]["properties"].get("docker")
    if deploys and not re.search(r"cosign|sigstore|slsa|provenance|attest", text, re.I):
        model.observe(
            rule="C10",
            theme="provenance",
            title="Deploy path has no artifact signature check",
            stage="deploy",
            node_id=workflow,
            file=rel,
            line=1,
            evidence="deploy without signature verification",
            recommendation=rule_recommendation("C10"),
            exposure="untrusted_trigger" if untrusted_entry else "internal",
            privilege="deploy",
            asset="production",
            exploitability="misconfiguration",
            identity=False,
        )


def _terraform_network(model: RepoModel, rel: str, text: str) -> None:
    if re.search(r'http_tokens\s*=\s*"optional"', text, re.I):
        cloud = model.node("cloud", "Instance metadata service", lane="credential", unique=True, file=rel, properties={"service": "imds", "imdsv1": True})
        model.observe(
            rule="S01",
            theme="metadata",
            title="Instance metadata allows the tokenless v1 path",
            stage="credential",
            node_id=cloud,
            file=rel,
            line=_line_of(text, "http_tokens"),
            evidence='http_tokens = "optional"',
            recommendation=rule_recommendation("S01"),
            exposure="internal",
            privilege="credential",
            asset="credential",
            exploitability="misconfiguration",
            identity=False,
        )
    if "0.0.0.0/0" in text:
        window_start = max(0, text.find("0.0.0.0/0") - 240)
        window = text[window_start:text.find("0.0.0.0/0") + 40].lower()
        egress = "egress" in window and "ingress" not in window
        if egress:
            node = model.node("cloud", "Unrestricted egress", lane="deploy", unique=True, file=rel, properties={"open_network": True})
            model.observe(
                rule="S06",
                theme="open_network",
                title="Security rule allows egress to the whole internet",
                stage="exploit",
                node_id=node,
                file=rel,
                line=_line_of(text, "0.0.0.0/0"),
                evidence="0.0.0.0/0",
                recommendation=rule_recommendation("S06"),
                exposure="public",
                privilege="ssrf",
                asset="internal",
                exploitability="misconfiguration",
                identity=False,
            )
        else:
            exposure = model.node("exposure", "Open security group", lane="entry", unique=True, file=rel, properties={"open_network": True})
            model.observe(
                rule="S04",
                theme="open_network",
                title="Security rule accepts traffic from the whole internet",
                stage="entry",
                node_id=exposure,
                file=rel,
                line=_line_of(text, "0.0.0.0/0"),
                evidence="0.0.0.0/0",
                recommendation=rule_recommendation("S04"),
                exposure="public",
                privilege="admin",
                asset="production",
                exploitability="misconfiguration",
                identity=False,
            )
    if re.search(r"publicly_accessible\s*=\s*true", text, re.I):
        store = model.node("datastore", "Public database", lane="data", unique=True, file=rel, properties={"public": True, "sensitive": True})
        exposure = model.node("exposure", "Public database", lane="entry", unique=True, file=rel, properties={"public_storage": True})
        model.edge(exposure, store, "ROUTES_TO", file=rel, evidence="publicly_accessible")
        model.observe(
            rule="S08",
            theme="public_bucket",
            title="Database accepts public connections",
            stage="data",
            node_id=store,
            file=rel,
            line=_line_of(text, "publicly_accessible"),
            evidence="publicly_accessible = true",
            recommendation=rule_recommendation("S08"),
            exposure="public",
            privilege="exposed_data",
            asset="sensitive",
            exploitability="misconfiguration",
            identity=False,
        )
    if re.search(r'resource\s+"aws_iam_role"', text) and re.search(r'Principal\s*=\s*"\*"', text):
        role = model.node("cloud", "Cross-account role", lane="credential", unique=True, file=rel, properties={"assume_role": True})
        model.observe(
            rule="S05",
            theme="iam",
            title="Role trust allows any principal to assume it",
            stage="credential",
            node_id=role,
            file=rel,
            line=_line_of(text, "Principal"),
            evidence='Principal = "*"',
            recommendation=rule_recommendation("S05"),
            exposure="internal",
            privilege="admin",
            asset="production",
            exploitability="misconfiguration",
            identity=True,
        )
    if "aws_iam_access_key" in text or re.search(r'resource\s+"aws_iam_user"', text):
        user = model.node("cloud", "Long-lived IAM user", lane="credential", unique=True, file=rel, properties={"static_user": True})
        model.observe(
            rule="S07",
            theme="credential",
            title="Account keeps a long-lived IAM user",
            stage="credential",
            node_id=user,
            file=rel,
            line=1,
            evidence="aws_iam_user",
            recommendation=rule_recommendation("S07"),
            exposure="internal",
            privilege="credential",
            asset="credential",
            exploitability="misconfiguration",
            identity=True,
        )
    if re.search(r"endpoint_public_access\s*=\s*true", text, re.I):
        plane = model.node("cloud", "Public control plane", lane="entry", unique=True, file=rel, properties={"public_control": True})
        exposure = model.node("exposure", "Public control plane", lane="entry", unique=True, file=rel, properties={"open_network": True})
        model.edge(exposure, plane, "ROUTES_TO", file=rel, evidence="endpoint_public_access")
        model.observe(
            rule="S03",
            theme="open_network",
            title="Cluster API is reachable from the internet",
            stage="entry",
            node_id=plane,
            file=rel,
            line=_line_of(text, "endpoint_public_access"),
            evidence="endpoint_public_access = true",
            recommendation=rule_recommendation("S03"),
            exposure="public",
            privilege="admin",
            asset="production",
            exploitability="misconfiguration",
            identity=False,
        )


def analyze_cloudformation(model: RepoModel, rel: str, text: str) -> None:
    if "AWS::S3::Bucket" in text and re.search(r"PublicRead|Principal:\s*['\"]?\*", text):
        bucket = model.node("bucket", rel, file=rel, line=1, lane="data", unique=True, properties={"provider": "s3", "public": True, "sensitive": "Sensitive" in text})
        exposure = model.node("exposure", f"Public object storage {rel}", lane="entry", unique=True, properties={"public_storage": True})
        model.edge(exposure, bucket, "ROUTES_TO", file=rel, evidence="PublicRead")
        model.observe(
            rule="S08",
            theme="public_bucket",
            title="CloudFormation bucket is world-readable",
            stage="data",
            node_id=bucket,
            file=rel,
            line=_line_of(text, "AWS::S3::Bucket"),
            evidence="PublicRead",
            recommendation=rule_recommendation("S08"),
            exposure="public",
            privilege="exposed_data",
            asset="sensitive" if "Sensitive" in text else "internal",
            exploitability="misconfiguration",
            identity=False,
        )
    if "0.0.0.0/0" in text:
        _terraform_network(model, rel, text)
    if re.search(r"Action:\s*['\"]?\*['\"]?", text) and re.search(r"Resource:\s*['\"]?\*['\"]?", text):
        policy = model.node("cloud", "Wildcard IAM policy", lane="credential", unique=True, file=rel, properties={"wildcard": True})
        model.observe(
            rule="U07",
            theme="iam",
            title="CloudFormation policy allows every action on every resource",
            stage="credential",
            node_id=policy,
            file=rel,
            line=_line_of(text, "Action"),
            evidence="Action * Resource *",
            recommendation=rule_recommendation("U07"),
            exposure="internal",
            privilege="admin",
            asset="production",
            exploitability="misconfiguration",
            identity=False,
        )
    if re.search(r"HttpTokens:\s*optional", text, re.I):
        cloud = model.node("cloud", "Instance metadata service", lane="credential", unique=True, file=rel, properties={"service": "imds", "imdsv1": True})
        model.observe(
            rule="S01",
            theme="metadata",
            title="CloudFormation enables the tokenless metadata path",
            stage="credential",
            node_id=cloud,
            file=rel,
            line=_line_of(text, "HttpTokens"),
            evidence="HttpTokens: optional",
            recommendation=rule_recommendation("S01"),
            exposure="internal",
            privilege="credential",
            asset="credential",
            exploitability="misconfiguration",
            identity=False,
        )


def analyze_sql(model: RepoModel, rel: str, text: str) -> None:
    checks = (
        (r"xp_cmdshell|COPY\s+\S+\s+FROM\s+PROGRAM", "D01", "host_exec", "Database statement can start a host process", "D01"),
        (r"postgres_fdw|dblink\s*\(|FOREIGN\s+DATA\s+WRAPPER|linked\s+server", "D02", "datastore_trust", "Database trusts another datastore", "D02"),
        (r"GRANT\s+ALL\b", "D03", "db_admin", "Database grants every privilege", "D03"),
        (r"INTO\s+OUTFILE|INTO\s+DUMPFILE|pg_read_file|lo_export", "D08", "db_egress", "Database can read or write outside its tables", "D08"),
    )
    for pattern, rule, theme, title, _same in checks:
        match = re.search(pattern, text, re.I)
        if not match:
            continue
        store = model.node("datastore", "SQL database", lane="data", unique=True, file=rel, properties={"sensitive": True})
        model.observe(
            rule=rule,
            theme=theme,
            title=title,
            stage="data",
            node_id=store,
            file=rel,
            line=_line_of(text, match.group(0)),
            evidence=match.group(0)[:80],
            recommendation=rule_recommendation(rule),
            exposure="internal",
            privilege="data",
            asset="sensitive",
            exploitability="misconfiguration",
            identity=False,
        )


def analyze_ai(model: RepoModel, rel: str, text: str) -> None:
    agent = bool(re.search(r"AgentExecutor|initialize_agent|create_react_agent|create_tool_calling_agent", text))
    dangerous_tool = bool(re.search(r"ShellTool|python_repl|terminal|subprocess|requests\.(get|post)", text))
    if agent and dangerous_tool:
        node = _ai_node(model, rel, text)
        model.observe(
            rule="A04",
            theme="ai_tool",
            title="Agent can call a shell or network tool",
            stage="exploit",
            node_id=node,
            file=rel,
            line=_line_of(text, "Agent"),
            evidence="agent tool",
            recommendation=rule_recommendation("A04"),
            exposure="public",
            privilege="rce" if re.search(r"ShellTool|python_repl|terminal|subprocess", text) else "ssrf",
            asset="production",
            exploitability="user_controlled",
            identity=False,
        )
        if agent and not re.search(r"max_iterations\s*=", text):
            model.observe(
                rule="A09",
                theme="agency",
                title="Agent loop has no iteration cap",
                stage="exploit",
                node_id=node,
                file=rel,
                line=_line_of(text, "Agent"),
                evidence="missing max_iterations",
                recommendation=rule_recommendation("A09"),
                exposure="public",
                privilege="logic",
                asset="production",
                exploitability="user_controlled",
                identity=False,
            )
    if re.search(r"pickle\.loads|torch\.load|joblib\.load|cloudpickle\.load", text):
        node = _ai_node(model, rel, text)
        model.observe(
            rule="A02",
            theme="model_load",
            title="Model load uses an executable serialization format",
            stage="exploit",
            node_id=node,
            file=rel,
            line=1,
            evidence="executable model load",
            recommendation=rule_recommendation("A02"),
            exposure="public",
            privilege="rce",
            asset="production",
            exploitability="user_controlled",
            identity=False,
        )
    if re.search(r"similarity_search|as_retriever", text) and not re.search(r"\bfilter\s*=", text):
        node = _ai_node(model, rel, text)
        model.observe(
            rule="A07",
            theme="rag",
            title="Vector search has no pre-retrieval filter",
            stage="data",
            node_id=node,
            file=rel,
            line=1,
            evidence="similarity_search",
            recommendation=rule_recommendation("A07"),
            exposure="public",
            privilege="data",
            asset="sensitive",
            exploitability="user_controlled",
            identity=False,
        )


def analyze_embedded_secret(model: RepoModel, rel: str, text: str) -> None:
    if re.search(r"AKIA[0-9A-Z]{16}", text) or "BEGIN PRIVATE KEY" in text or "BEGIN RSA PRIVATE KEY" in text:
        secret = model.node("secret", "Embedded repository credential", lane="credential", unique=True, file=rel)
        model.observe(
            rule="U02",
            theme="credential",
            title="Repository contains a static credential",
            stage="credential",
            node_id=secret,
            file=rel,
            line=1,
            evidence="static credential material",
            recommendation=rule_recommendation("U02"),
            exposure="internal",
            privilege="credential",
            asset="credential",
            exploitability="misconfiguration",
            identity=False,
        )


def _ai_node(model: RepoModel, rel: str, text: str) -> str:
    node = model.node("workload", f"AI agent {rel}", lane="service", unique=True, file=rel, properties={"ai_entry": True})
    for existing in list(model.nodes.values()):
        if existing["kind"] == "endpoint" and existing.get("file") == rel:
            model.edge(existing["id"], node, "CALLS", file=rel, evidence="handler reaches agent", confidence="INFERRED")
    return node


def looks_like_cloudformation(text: str) -> bool:
    return "AWSTemplateFormatVersion" in text or "AWS::IAM::" in text or "AWS::S3::" in text or "AWS::EC2::" in text

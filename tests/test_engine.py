from pathlib import Path

import pytest

from pathfinder.analyze import analyze
from pathfinder.graphview import render_graph_html
from pathfinder.report import pr_comment, render_html
from pathfinder.threatmodel import render_threat_html
from pathfinder.scoring import score_path

@pytest.fixture
def payment_repo(tmp_path: Path) -> Path:
    files = {
        "api/public_api.py": '''from flask import Flask, request\n\nfrom services.billing import settle\nfrom services.user_service import load_user\n\napp = Flask(__name__)\n\n\n@app.route("/api/payment", methods=["POST"])\ndef pay():\n    body = request.get_json(silent=True) or {}\n    load_user(body.get("user_id"))\n    return settle(body)\n''',
        "services/user_service.py": '''def load_user(user_id):\n    query = "SELECT * FROM users WHERE id = " + str(user_id)\n    return cursor.execute(query)\n''',
        "services/admin_service.py": '''def approve_refund(body):\n    amount = body.get("amount")\n    return issue_wallet_credit(amount)\n\n\ndef issue_wallet_credit(amount):\n    return wallet_credit(amount)\n\n\ndef wallet_credit(amount):\n    return amount\n''',
        "services/billing.py": '''import boto3\nimport requests\n\nfrom services.admin_service import approve_refund\n\n\ndef settle(body):\n    role = body.get("role")\n    if role != "guest":\n        approve_refund(body)\n    callback = body.get("callback")\n    fetch_callback(callback)\n    credentials = read_role_credentials()\n    return read_receipts(credentials)\n\n\ndef fetch_callback(url):\n    return requests.get(url, timeout=3)\n\n\ndef read_role_credentials():\n    return requests.get(\n        "http://169.254.169.254/latest/meta-data/iam/security-credentials/payment-role",\n        timeout=3,\n    ).text\n\n\ndef read_receipts(credentials):\n    client = boto3.client("s3")\n    return client.get_object(Bucket="acme-pay-receipts", Key="receipts/latest.csv")\n''',
        "web/server.js": '''const express = require("express");\nconst app = express();\n\napp.post("/api/notify", (req, res) => {\n  const callback = req.body.callback;\n  fetch(callback).then((response) => response.text()).then((body) => res.send(body));\n});\n''',
        ".github/workflows/deploy.yml": '''name: deploy\non:\n  pull_request_target:\n    types: [opened, synchronize]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v2\n      - name: install\n        run: pip install -r requirements.txt\n      - name: title\n        run: echo "${{ github.event.pull_request.title }}"\n      - name: creds\n        run: echo "${{ secrets.PROD_AWS_SECRET_ACCESS_KEY }}" > aws.cred\n      - name: image\n        run: docker build -t acme-pay:latest .\n      - name: ship\n        run: kubectl apply -f k8s/payment.yaml\n''',
        "Dockerfile": '''FROM python:3.11\nUSER root\nARG AWS_SECRET\nRUN apt-get update && apt-get install -y curl\nCOPY . /app\nCMD ["python", "api/public_api.py"]\n''',
        "k8s/payment.yaml": '''apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: payment\nspec:\n  replicas: 2\n  selector:\n    matchLabels:\n      app: payment\n  template:\n    metadata:\n      labels:\n        app: payment\n    spec:\n      containers:\n        - name: payment\n          image: acme-pay:latest\n          securityContext:\n            privileged: true\n          env:\n            - name: AWS_SECRET_ACCESS_KEY\n              valueFrom:\n                secretKeyRef:\n                  name: prod-secrets\n                  key: aws\n''',
        "terraform/storage.tf": '''resource "aws_s3_bucket" "receipts" {\n  bucket = "acme-pay-receipts"\n  tags = {\n    DataClassification = "sensitive"\n  }\n}\n\nresource "aws_s3_bucket_acl" "receipts" {\n  bucket = aws_s3_bucket.receipts.id\n  acl    = "public-read"\n}\n\nresource "aws_iam_role_policy" "payment" {\n  policy = jsonencode({\n    Statement = [{\n      Action   = "*"\n      Resource = "*"\n      Effect   = "Allow"\n    }]\n  })\n}\n''',
        "openapi.yaml": '''openapi: 3.0.3\ninfo:\n  title: Payment API\n  version: "1.0.0"\npaths:\n  /api/payment:\n    post:\n      operationId: pay\n      security: []\n      responses:\n        "200":\n          description: accepted\n''',
        "requirements.txt": "flask\nrequests\nboto3\npyyaml\n",
    }
    for relative, text in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp_path


def test_payment_chain_is_one_path(payment_repo: Path):
    result = analyze(payment_repo)
    assert result["parse_errors"] == []
    cloud = [path for path in result["paths"] if path["category"] == "cloud_escalation"]
    assert cloud, [path["narrative"] for path in result["paths"]]
    narrative = cloud[0]["narrative"]
    cursor = 0
    for part in [
        "Public API",
        "POST /api/payment",
        "Auth bypass",
        "Internal service billing.settle",
        "SSRF",
        "Metadata service",
        "Cloud role credentials",
        "S3 bucket acme-pay-receipts",
        "Sensitive data",
    ]:
        index = narrative.find(part, cursor)
        assert index >= 0, narrative
        cursor = index
    assert cloud[0]["band"] == "Critical"
    product = cloud[0]["exposure"] * cloud[0]["privilege"] * cloud[0]["asset"] * cloud[0]["exploitability"]
    assert abs(cloud[0]["score"] - round(product * 100)) <= 1


def test_parallel_paths_and_scorecard(payment_repo: Path):
    result = analyze(payment_repo)
    categories = {path["category"] for path in result["paths"]}
    assert {"injection", "business_logic", "supply_chain", "data_exposure"} <= categories
    supply = next(path for path in result["paths"] if path["category"] == "supply_chain")
    assert "pull_request_target" in supply["narrative"]
    assert "payment" in supply["narrative"]
    assert supply["band"] in {"Critical", "High"}
    payment = next(item for item in result["components"] if item["receives"] == "POST /api/payment")
    assert "settle" in payment["calls"]
    assert result["scorecard"]["critical_paths"] >= 1
    assert result["scorecard"]["cloud_paths"] >= 1
    assert result["scorecard"]["supply_chain_paths"] >= 1
    assert result["per"]["eligible"] == len(result["paths"])
    assert result["per"]["erased"] == 0
    assert any(item["rule"] == "U07" for item in result["findings"])


def test_objective_search_reaches_the_chosen_target(payment_repo: Path):
    from pathfinder.cli import main
    from pathfinder.query import search, translate

    result = analyze(payment_repo)
    secret = search(result, {"name": "secrets", "start": ["public-endpoint"], "target": ["secret"]})
    assert secret["found"] >= 1
    assert secret["paths"][0]["band"] in {"Critical", "High"}
    assert any("AUTHORIZATION_CHECK" in path["missing_controls"] for path in secret["paths"])
    pii = search(result, {"name": "pii", "start": ["public-endpoint"], "target": ["pii-database"], "conditions": ["user_input_reachable"]})
    assert pii["found"] >= 1
    financial = search(result, translate("Show me paths where a public API could reach financial records."))
    assert financial["target"] == ["FINANCIAL_DATA"]
    assert financial["found"] >= 1
    admin = search(result, {"name": "iam", "start": ["application"], "target": ["iam-admin"]})
    assert admin["found"] >= 1
    assert result["scorecard"]["objectives"] >= 1
    assert any(item["name"] == "Slight misses" and item["found"] for item in result["hypotheses"])
    assert "Objectives an attacker can reach" in pr_comment(result)
    code = main(["find-path", str(payment_repo), "--from", "public-endpoint", "--to", "secret"])
    assert code == 0


def test_missing_control_rejects_an_authorized_walk():
    from pathfinder.query import search

    result = {
        "nodes": [
            {
                "id": "e",
                "kind": "endpoint",
                "name": "POST /admin/refund",
                "receives": "POST /admin/refund",
                "file": "a.py",
                "line": 1,
                "properties": {"auth": False, "method": "POST", "path": "/admin/refund"},
                "component": "POST /admin/refund",
            },
            {
                "id": "s",
                "kind": "secret",
                "name": "AWS_SECRET_KEY",
                "file": "a.py",
                "line": 4,
                "properties": {},
                "component": "AWS_SECRET_KEY",
            },
        ],
        "edges": [
            {
                "source": "e",
                "target": "s",
                "kind": "USES_SECRET",
                "file": "a.py",
                "line": 4,
                "evidence": "AWS_SECRET_KEY",
                "confidence": "EXTRACTED",
            }
        ],
        "observations": [],
        "paths": [],
        "scorecard": {},
        "root": ".",
    }
    open_walk = search(
        result,
        {
            "name": "open",
            "start": ["user"],
            "target": ["secret"],
            "must_not_have": ["AUTHORIZATION_CHECK", "MFA"],
        },
    )
    assert open_walk["found"] == 1
    assert "MFA" in open_walk["paths"][0]["missing_controls"]
    result["nodes"][0]["properties"]["auth"] = True
    closed = search(
        result,
        {"name": "closed", "start": ["user"], "target": ["secret"], "must_not_have": ["AUTHORIZATION_CHECK"]},
    )
    assert closed["found"] == 0


def test_html_and_comment_carry_the_chain(payment_repo: Path):
    result = analyze(payment_repo)
    html = render_html(result)
    narrative = next(path["narrative"] for path in result["paths"] if path["category"] == "cloud_escalation")
    assert narrative in html
    assert "Risk score" in html
    assert "Findings on this path" in html
    assert "For the exception record" in html
    comment = pr_comment(result)
    assert "Auth bypass" in comment
    assert "Static review only" in comment
    assert "Threat model" in comment
    assert "graph.html" in html
    graph = result["graph"]
    assert graph["schema_version"] == 1
    assert graph["god_nodes"]
    assert graph["communities"]
    confidences = {edge["confidence"] for edge in result["edges"]}
    assert confidences == {"EXTRACTED", "INFERRED"}
    cloud = next(path for path in result["paths"] if path["category"] == "cloud_escalation")
    assert cloud["confidence"] == "INFERRED"
    page = render_graph_html(result)
    assert "EXTRACTED" in page and "INFERRED" in page and "<canvas" in page
    assert "Paths to eliminate" in page
    assert "What to remove" in page
    recommendation = next(text for path in result["paths"] if path.get("recommendations") for text in path["recommendations"])
    assert recommendation in page
    threat = render_threat_html(result)
    assert "Threats to eliminate" in threat
    assert "STRIDE" in threat
    assert "DREAD" in threat
    assert "PASTA" in threat
    assert recommendation in threat
    from pathfinder.threatmodel import build_threat_model
    modeled = build_threat_model(result)
    criticals = [item for item in modeled["threats"] if item["band"] == "Critical"]
    assert criticals
    assert criticals[0]["why"]
    assert criticals[0]["effect"].startswith("Effect:")
    assert criticals[0]["recommendation"]
    assert criticals[0]["reachability"]
    assert criticals[0]["exploitability_level"]
    assert "threat-model.html" in html


def test_other_languages_and_gitlab(tmp_path: Path):
    (tmp_path / "AdminController.java").write_text(
        """
        @RestController
        public class AdminController {
          @GetMapping("/admin/export")
          public void export(String url) throws Exception {
            new URL(url).openStream();
          }
        }
        """,
        encoding="utf-8",
    )
    (tmp_path / "main.go").write_text(
        """
        package main
        import "net/http"
        import "os/exec"
        func main() { http.HandleFunc("/admin/run", run) }
        func run(w http.ResponseWriter, r *http.Request) { exec.Command("sh", r.URL.Query().Get("x")).Run() }
        """,
        encoding="utf-8",
    )
    (tmp_path / "routes.php").write_text(
        """
        <?php
        Route::post('/api/payment', function () {
          $id = $_GET['id'];
          mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
        });
        """,
        encoding="utf-8",
    )
    (tmp_path / ".gitlab-ci.yml").write_text(
        """
        deploy:
          script:
            - echo "$secrets.DEPLOY_KEY"
            - kubectl apply -f k8s
          rules:
            - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
        """,
        encoding="utf-8",
    )
    (tmp_path / "k8s.yaml").write_text(
        """
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: api
        spec:
          template:
            spec:
              containers:
                - name: api
                  image: api:latest
        """,
        encoding="utf-8",
    )
    result = analyze(tmp_path)
    categories = {path["category"] for path in result["paths"]}
    assert "exploit_primitive" in categories
    assert "remote_execution" in categories
    assert "injection" in categories
    assert "supply_chain" in categories


def test_install_hook_writes_into_the_other_repo(tmp_path: Path):
    from pathfinder.install import PUBLIC_REF, InstallError, install

    destination = install(tmp_path)
    text = destination.read_text(encoding="utf-8")
    published = (Path(__file__).resolve().parents[1] / "install" / "github" / "attack-paths.yml").read_text(encoding="utf-8")
    assert text == published
    assert destination == tmp_path / ".github" / "workflows" / "attack-paths.yml"
    assert f"uses: TemTech-Solutions/attack-path-elimination@{PUBLIC_REF}" in text
    assert "https://github.com/TemTech-Solutions/attack-path-elimination" in text
    assert "actions/checkout@11d5960a326750d5838078e36cf38b85af677262" in text
    assert "pull_request_target" not in text
    try:
        install(tmp_path, tool="TemTech-Solutions/attack-path-elimination")
        raise AssertionError("second install should refuse to overwrite")
    except InstallError:
        pass
    gitlab = install(tmp_path, platform="gitlab", tool="TemTech-Solutions/attack-path-elimination", force=True)
    gitlab_text = gitlab.read_text(encoding="utf-8")
    assert gitlab.name == "attack-paths.gitlab-ci.yml"
    assert "python -m pathfinder analyze ." in gitlab_text
    assert f"fetch --depth 1 origin {PUBLIC_REF}" in gitlab_text
    azure = install(tmp_path, platform="azure", force=True)
    azure_text = azure.read_text(encoding="utf-8")
    published_azure = (Path(__file__).resolve().parents[1] / "install" / "azure" / "attack-paths.yml").read_text(encoding="utf-8")
    assert azure == tmp_path / "azure-pipelines" / "attack-paths.yml"
    assert azure_text == published_azure
    assert f"fetch --depth 1 origin {PUBLIC_REF}" in azure_text
    assert "artifact: attack-path-report" in azure_text
    assert "python -m pip install --upgrade pip" in azure_text
    again = install(tmp_path, platform="azure-devops", force=True)
    assert again.read_text(encoding="utf-8") == azure_text
    action = (Path(__file__).resolve().parents[1] / "action.yml").read_text(encoding="utf-8")
    assert "python -m pathfinder analyze" in action
    assert "full commit SHA" in action
    assert "ref_is_allowed" in action
    assert "pull_request_target" not in action


def test_marketplace_release_tags_run_and_branches_do_not():
    from pathfinder.action_ref import ref_is_allowed

    assert ref_is_allowed("v1.0.2")
    assert ref_is_allowed("v1")
    assert ref_is_allowed("refs/tags/v1.0.2")
    assert ref_is_allowed("93268821c88ffe1e5b6bab91e493c3c8ed9187b9")
    assert not ref_is_allowed("main")
    assert not ref_is_allowed("master")
    assert not ref_is_allowed("vkt")
    assert not ref_is_allowed("")


def test_subtractive_families_compose(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        '''from langchain.agents import AgentExecutor
tools = [ShellTool()]
agent = AgentExecutor(tools=tools)
''',
        encoding="utf-8",
    )
    (tmp_path / "load_model.py").write_text("import torch\ntorch.load('model.bin')\n", encoding="utf-8")
    (tmp_path / "net.tf").write_text(
        '''resource "aws_security_group_rule" "admin" {
  cidr_blocks = ["0.0.0.0/0"]
  from_port   = 22
  to_port     = 22
  type        = "ingress"
}
''',
        encoding="utf-8",
    )
    (tmp_path / "db.sql").write_text("EXEC xp_cmdshell 'whoami';\nGRANT ALL ON customers TO app;\n", encoding="utf-8")
    (tmp_path / "stack.yml").write_text(
        """
        AWSTemplateFormatVersion: '2010-09-09'
        Resources:
          Api:
            Type: AWS::EC2::Instance
            Properties:
              MetadataOptions:
                HttpTokens: optional
        """,
        encoding="utf-8",
    )
    result = analyze(tmp_path)
    rules = {item["rule"] for item in result["findings"]}
    assert {"A04", "A02", "A09", "S04", "D01", "D03", "S01"} <= rules
    categories = {path["category"] for path in result["paths"]}
    assert "ai_agency" in categories
    assert "network_exposure" in categories
    assert "model_execution" in categories
    assert result["scorecard"]["control_families"]["AI"] >= 1
    assert result["scorecard"]["control_families"]["AWS"] >= 1
    assert result["scorecard"]["control_families"]["Datastore"] >= 1
    assert result["scorecard"]["hierarchy"] == "deletion > constraint"
    ai = next(path for path in result["paths"] if path["category"] == "ai_agency")
    assert ai["recommendations"]
    assert ai["recommendations"][0].startswith("Deletion:")


def test_every_language_keeps_a_diagnosable_path(tmp_path: Path):
    (tmp_path / "admin.rb").write_text(
        """
        class Admin
          custodian_key = "k9s-local-7f3a2c"
          def custodian_wrap
          end
          get '/admin/refund' do
            system(params[:cmd])
            db.query("SELECT * FROM users WHERE id = " + params[:id])
          end
        end
        """,
        encoding="utf-8",
    )
    (tmp_path / "export.rs").write_text(
        """
        #[get("/admin/export")]
        fn export_admin(q: String) {
            std::process::Command::new("sh");
        }
        """,
        encoding="utf-8",
    )
    (tmp_path / "Dump.kt").write_text(
        """
        @GetMapping("/admin/export")
        fun dump(url: String) {
          URL(url).openStream()
        }
        """,
        encoding="utf-8",
    )
    (tmp_path / "job.zzlang").write_text(
        """
        function open_admin(callback) {
          fetch(callback);
        }
        get "/admin/open"
        verify = False
        """,
        encoding="utf-8",
    )
    (tmp_path / "runner.c").write_text("void admin_run(char *cmd) { system(cmd); }\n", encoding="utf-8")
    (tmp_path / ".env").write_text("custodian_key=k9s-local-7f3a2c\n", encoding="utf-8")
    result = analyze(tmp_path)
    languages = {node.get("language") for node in result["nodes"]}
    assert {"ruby", "rust", "kotlin", "c"} <= languages
    categories = {path["category"] for path in result["paths"]}
    assert "remote_execution" in categories or "injection" in categories
    assert any(item.get("theme") == "review" for item in result["findings"])
    assert any("custodian_wrap" in (item.get("evidence") or "") for item in result["findings"])
    assert result["adaptation"]["promoted"] >= 1
    page = render_graph_html(result)
    assert "Diagnosis" in page
    assert "Clear path" in page
    assert "Next step" in page
    assert "Paths to eliminate" in page
    assert "What to remove" in page
    threat = render_threat_html(result)
    assert "Next step" in threat
    assert any(item.get("rule") == "APP05" for item in result["findings"])


def test_remediation_false_positives_are_left_out(tmp_path: Path):
    from pathfinder.cli import main
    from pathfinder.threatmodel import build_threat_model

    (tmp_path / "note.py").write_text('message = "the system is down"\nbind = "0.0.0.0"\n', encoding="utf-8")
    (tmp_path / "sample.env").write_text("token=placeholder-value\ncache_key=user-session\n", encoding="utf-8")
    (tmp_path / "admin.rb").write_text("get '/admin/run' do\n  system(params[:cmd])\nend\n", encoding="utf-8")
    (tmp_path / "marked.rb").write_text(
        "# pathfinder: false-positive: sandbox helper, not production\nget '/admin/tool' do\n  system(params[:cmd])\nend\n",
        encoding="utf-8",
    )
    first = analyze(tmp_path)
    assert not any("the system is down" in (item.get("evidence") or "") for item in first["findings"])
    assert not any(item.get("file") == "sample.env" for item in first["findings"])
    assert any("0.0.0.0" in (item.get("evidence") or "") for item in first["findings"])
    hit = next(item for item in first["findings"] if item.get("rule") == "APP05" and item.get("file") == "admin.rb")
    (tmp_path / "other.rb").write_text("get '/admin/other' do\n  system(params[:cmd])\nend\n", encoding="utf-8")
    (tmp_path / "loose.rb").write_text("get '/admin/loose' do\n  system(params[:cmd])\nend\n", encoding="utf-8")
    (tmp_path / "keep.rb").write_text(
        "get '/admin/keep' do\n  system(params[:cmd])\nend\n" + ("\n" * 30) + "def later\n  system(params[:other])\nend\n",
        encoding="utf-8",
    )
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "pathfinder-exceptions.yml").write_text(
        "exceptions:\n"
        "  - rule: APP5\n    file: other.rb\n    line: 2\n    reason: Fixture helper kept for the lab\n"
        "  - file: loose.rb\n    reason: Lab double, not a production route\n"
        "  - rule: APP05\n    file: keep.rb\n    line: 2\n    reason: First helper only, the later call stays\n",
        encoding="utf-8",
    )
    assert main(["except", str(tmp_path), "--rule", "APP05", "--file", "admin.rb", "--line", str(hit["line"]), "--reason", "Approved test double for the admin console", "--by", "remediation"]) == 0
    assert (tmp_path / "pathfinder-exceptions.yml").is_file()
    second = analyze(tmp_path)
    assert not any(item.get("rule") == "APP05" and item.get("file") == "admin.rb" for item in second["findings"])
    assert not any(item.get("rule") == "APP05" and item.get("file") == "other.rb" for item in second["findings"])
    assert any(item.get("file") == "loose.rb" for item in second["findings"])
    assert any(item.get("rule") == "APP05" and item.get("file") == "keep.rb" and (item.get("line") or 0) > 12 for item in second["findings"])
    assert not any(item.get("rule") == "APP05" and item.get("file") == "keep.rb" and (item.get("line") or 0) <= 12 for item in second["findings"])
    assert any("0.0.0.0" in (item.get("evidence") or "") for item in second["findings"])
    assert any(item.get("file") == "admin.rb" and item.get("rule") == "APP05" for item in second["suppressed"])
    assert not any(item.get("rule") == "APP05" and item.get("file") == "marked.rb" for item in second["findings"])
    assert any(item.get("file") == "marked.rb" for item in second["suppressed"])
    modeled = build_threat_model(second)
    assert modeled["suppressed"]
    assert not any(
        hop.get("rule") == "APP05" and str(hop.get("file") or "").endswith("admin.rb")
        for item in modeled["threats"]
        for hop in item.get("hops") or []
    )
    assert not any(
        hop.get("rule") == "APP05" and str(hop.get("file") or "").endswith("admin.rb")
        for path in second["paths"]
        for hop in path.get("hops") or []
    )
    assert "Threat model" in pr_comment(second)
    threat = render_threat_html(second)
    assert "Exceptions" in threat
    assert "Approved test double for the admin console" in threat
    assert "sandbox helper, not production" in threat


def test_local_learner_holds_placeholder_names(tmp_path: Path):
    from pathfinder.threatmodel import build_threat_model

    (tmp_path / "admin.rb").write_text(
        "class Admin\n"
        "  def example_placeholder_fixture\n"
        "  end\n"
        "  get '/admin/run' do\n"
        "    system(params[:cmd])\n"
        "  end\n"
        "end\n",
        encoding="utf-8",
    )
    result = analyze(tmp_path)
    assert any(item.get("rule") == "APP05" and item.get("file") == "admin.rb" for item in result["findings"])
    assert not any("example_placeholder_fixture" in (item.get("evidence") or "") for item in result["findings"])
    modeled = build_threat_model(result)
    assert not any(
        "example_placeholder_fixture" in (hop.get("evidence") or "")
        for item in modeled["threats"]
        for hop in item.get("hops") or []
    )


def test_score_bands():
    critical = score_path({"public"}, {"credential"}, {"sensitive"}, {"user_controlled", "missing_auth"})
    assert critical["band"] == "Critical"
    assert critical["score"] >= 85
    low = score_path({"internal"}, {"none"}, {"internal"}, {"heuristic_logic"})
    assert low["band"] == "Low"

from pathlib import Path

import pytest

from pathfinder.analyze import analyze
from pathfinder.graphview import render_graph_html
from pathfinder.report import pr_comment, render_html
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
    comment = pr_comment(result)
    assert "Auth bypass" in comment
    assert "Static review only" in comment
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
    from pathfinder.install import InstallError, install

    destination = install(tmp_path)
    text = destination.read_text(encoding="utf-8")
    published = (Path(__file__).resolve().parents[1] / "install" / "github" / "attack-paths.yml").read_text(encoding="utf-8")
    assert text == published
    assert destination == tmp_path / ".github" / "workflows" / "attack-paths.yml"
    assert "uses: TemTech-Solutions/attack-path-elimination@main" in text
    assert "https://github.com/TemTech-Solutions/attack-path-elimination" in text
    assert "actions/checkout@v4" in text
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
    action = (Path(__file__).resolve().parents[1] / "action.yml").read_text(encoding="utf-8")
    assert "python -m pathfinder analyze" in action
    assert "pull_request_target" not in action


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


def test_score_bands():
    critical = score_path({"public"}, {"credential"}, {"sensitive"}, {"user_controlled", "missing_auth"})
    assert critical["band"] == "Critical"
    assert critical["score"] >= 85
    low = score_path({"internal"}, {"none"}, {"internal"}, {"heuristic_logic"})
    assert low["band"] == "Low"

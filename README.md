# Attack path elimination

Attack path elimination reads a repository and answers one question: **can an attacker walk from an entry the files already contain to a crown jewel, and which edge should be deleted?**

It builds one graph from application code, pipelines, containers, and cloud configuration. A chain is that walk, kept together. A traditional scanner would often file the missing authorization check, the outbound call, the credential, and the data store as four separate tickets. This report states them as one path and names the edge to remove.

**This tool is built on the baseline published by the [OWASP Subtractive Hardening Top 10](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10).** The control IDs, the order of the fix, and the path-erasure measure come from that project. The repository that runs the scan is maintained by [TemTech-Solutions/attack-path-elimination](https://github.com/TemTech-Solutions/attack-path-elimination). It applies that baseline to a code, pipeline, and cloud snapshot. It is not an OWASP Foundation project, and it does not replace the upstream standard.

The analyzer parses files. It does not install the application, run its tests, or execute its code. It does not produce exploit procedures, payloads, or reproduction steps. The change it recommends is deletion of the edge, or a constraint when the edge cannot disappear. Deletion ranks ahead of constraint.

## What you get

Every scan writes three HTML views of the same snapshot:

| File | What it is for |
| --- | --- |
| `report.html` | Ranked chains, the scorecard, and the edge to remove |
| `graph.html` | The graph. Select an issue and the walk is laid out with the diagnosis and the next change |
| `threat-model.html` | The same findings grouped by severity, reachability, exploitability, STRIDE, DREAD, or PASTA |

A GitHub Actions run publishes them as the `attack-path-report` artifact and writes the short form into the job summary. On a pull request it updates one comment. A GitLab job publishes the same files as artifacts. An Azure DevOps pipeline publishes the same artifact and, on an Azure Repos pull request, updates one comment. A local run writes them under `--out`.

## What a chain means

A chain means the files contain a connected walk from an entry to something valuable: a public route, an untrusted pipeline, or a public bucket, through calls and deploy edges, to credentials, data, or a production workload.

Confirm the file and line before you treat a hop as a defect. The score orders removal inside this snapshot. It is not a CVSS score, and it is not proof that a specific request would succeed.

```text
risk = exposure × privilege × asset × exploitability
```

Each factor is between 0 and 1. The published score is that product on a 0–100 scale. Critical is 85 and above, High is 70, Medium is 40, and Low is below that.

Path erasure rate is `P_erased / P_eligible`, the measure defined with that OWASP project. The first local run is the snapshot later runs compare against. A later run with the same `--out` folder counts a chain as erased when its narrative is gone. A GitHub, GitLab, or Azure DevOps run is a fresh scan of that commit and does not carry the earlier snapshot.

## Built on the OWASP Subtractive Hardening baseline

The analyzer is built from the baseline in the [OWASP Subtractive Hardening Top 10](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10), the OWASP Subtractive Security Top 10 Project. Three parts of that baseline are in this tool:

- **The control catalog.** Findings use the control IDs from the platform standards below. `pathfinder/baseline.py` stores each ID with a short engineering recommendation, so a report can name the edge to delete. The upstream document remains the standard.
- **The hierarchy of efficacy.** Architectural deletion comes before architectural constraint. Monitoring is not the fix this tool recommends. That order is the [Hierarchy of Efficacy](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10/blob/main/HierarchyOfEfficacy.md).
- **Path erasure.** A later local scan reports `P_erased / P_eligible`, the Path Erasure Rate those documents use to measure whether a path is gone. See [Path Erasure Precedence](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10/blob/main/PathErasurePrecedence.md) and the project's [PER](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10/tree/main/PER) notes.

The families this scan implements are the ones in that baseline for application code, pipelines, AWS, datastores, AI, and the universal laws:

| Family in the OWASP baseline | Control IDs | Upstream standard | What the scan looks for |
| --- | --- | --- | --- |
| Application | APP01–APP10 | [Application Hardening Top 10](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10/blob/main/ApplicationSubtractiveTop10.md) | Open routes, raw request bodies, tokens, dynamic execution, egress, query construction, weak authority |
| CI/CD | C01–C10 | [CI/CD Pipeline Subtractive Hardening Top 10](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10/blob/main/CICDPipelineSubtractiveTop10.md) | Secrets in jobs, privileged runners, floating dependencies and actions, untrusted triggers, unsigned deploys |
| AWS | S01–S10 | [AWS Subtractive Hardening Top 10](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10/blob/main/AWSSubtractiveTop10.md) | Tokenless metadata, wildcard trust, public control planes, open security groups, public data stores |
| Datastore | D01–D10 | [Datastore Subtractive Hardening Top 10](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10/blob/main/DatastoreSubtractiveTop10.md) | Host execution, linked databases, `GRANT ALL`, database file export |
| AI | A01–A10 | [AI Subtractive Hardening Top 10](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10/blob/main/AISubtractiveTop10.md) | Executable model loads, agent shell or network tools, uncapped loops, unfiltered retrieval |
| Universal | U01–U10 | [Universal Subtractive Security Laws](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10/blob/main/UniversalSubtractiveLaws.md) | Static credentials, open egress, wildcard privilege |

That same repository also publishes the operating standards around the baseline, including the [Subtractive Baselining Standard](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10/blob/main/SubtractiveBaselines.md), [Subtractive Exception Handling](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10/blob/main/SubtractiveExceptionHandling.md), and [Subtractive Threat Modeling](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10/blob/main/SubtractiveThreatModeling.md). In this tool, a recorded exception needs a reason. A later scan leaves that case out of the ranked paths, and the threat-model page still lists it.

Every walk is also tagged, when the evidence supports it, against:

- OWASP Top 10, API Security Top 10, ASVS
- OWASP CI/CD Top 10, Kubernetes Top 10, Docker Top 10, Serverless Top 10, LLM Top 10

The same walk can be read through STRIDE, DREAD, PASTA, LINDDUN, OCTAVE, Trike, VAST, and attack trees. MITRE ATT&CK is recorded as a tactic name only. The Lockheed Martin Kill Chain is a stage name only. These tags are a review vocabulary. They are not a certification, and they are not produced by sending the repository to an external model.

Shipped objective templates ask whether a walk exists for credential exposure, AWS privilege escalation, privilege escalation into an admin function, lateral movement, ransomware blast radius, PCI data, personal data, payment fraud, an unprotected admin path, production, source code, supply chain, and OWASP web, API, and LLM objectives.

## What the scan reads

Python is parsed with the standard library AST, including calls across files. Java, JavaScript, TypeScript, Go, C#, and PHP contribute routes and sinks from source patterns. Every other program file is read by one structural pass: routes, calls, string-built queries, outbound requests, dynamic execution, and credentials assigned in source. Extensionless scripts are included when the file is code.

A second pass records smaller structural signals: a disabled certificate check, a wildcard origin, a world-writable mode, a debug switch left on, an anonymous authorization exception, a redirect or file path taken from the request, a weak hash beside a credential, and caller-controlled markup.

A local centroid model learns identifier shapes from signals this repository already confirmed, stores them in `.pathfinder/environment.json`, and blends them into the next scan of that tree. Source stays on the machine. Learned names are additional review findings. They do not invent a walk the files do not contain.

Surrounding configuration is part of the same graph:

| Source | What it contributes |
| --- | --- |
| GitHub Actions, GitLab CI, Azure Pipelines | Triggers, secrets in jobs, deploy steps |
| Dockerfile | Root images, secrets in the build, shells and package tools |
| Kubernetes manifests | Privileged workloads, secrets in the environment |
| Terraform and CloudFormation | Buckets, network exposure, IAM and wildcard trust |
| OpenAPI | Declared operations and whether security is empty |
| SQL | Host execution, broad grants, sensitive tables |
| `requirements.txt`, `package.json` | Dependency edges |

Edges are `CALLS`, `ROUTES_TO`, `READS`, `FLOWS_TO`, `USES_SECRET`, `DEPLOYS`, `INVOKES`, and `TRUSTS`. An edge is `EXTRACTED` when the relationship is written in a file, and `INFERRED` when the analyzer resolved it across files or runtime configuration. A path's confidence is its weakest hop. Ambiguous calls are left unlinked.

Directories named `.git`, `node_modules`, `venv`, `.venv`, `__pycache__`, `dist`, `build`, `out`, `data`, `.pathfinder`, and `.pytest_cache` are skipped. Files larger than 1 MB are skipped.

A hit requires structural evidence: a call, a string-built query, a credential literal, a missing control, or one of the smaller signals above. A bare word such as `system`, a placeholder value (`placeholder`, `changeme`, `example`, `dummy`), or a cache key is not a finding.

## Integrate with GitHub Actions

From the repository you want to scan, add one workflow. The application stays in its own repository. GitHub checks that repository out and runs the analyzer from this action.

```bash
mkdir -p .github/workflows
curl -fsSL -o .github/workflows/attack-paths.yml \
  https://raw.githubusercontent.com/TemTech-Solutions/attack-path-elimination/main/install/github/attack-paths.yml
git add .github/workflows/attack-paths.yml
git commit -m "Add attack path scan"
git push
```

PowerShell:

```powershell
cd path\to\repository-to-scan
New-Item -ItemType Directory -Force .github\workflows | Out-Null
Invoke-WebRequest https://raw.githubusercontent.com/TemTech-Solutions/attack-path-elimination/main/install/github/attack-paths.yml -OutFile .github\workflows\attack-paths.yml
git add .github\workflows\attack-paths.yml
git commit -m "Add attack path scan"
git push
```

The workflow runs on pull requests and on pushes to `main` or `master`. The job checks the application out, then runs:

```yaml
uses: TemTech-Solutions/attack-path-elimination@be1e5ddba0f48bdda8f58887d5b18bcb3dcda508
```

That ref is a full commit SHA. The action refuses a branch or a tag before it analyzes anything, because a branch or tag can move after review. The published hook in this repository is rewritten to the new commit when `main` moves. A repository that already committed an older SHA keeps running that commit until someone replaces the workflow.

`actions/checkout`, `actions/setup-python`, and `actions/upload-artifact` inside the action are pinned to full commit SHAs as well. Pip is upgraded before the analyzer's dependencies are installed.

The calling workflow needs `contents: read` and, if pull-request comments are left on, `pull-requests: write`. Comments are a single updated note, marked `<!-- pathfinder-attack-paths -->`.

Optional inputs, if you call the action yourself instead of copying the hook:

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | Directory inside the checkout to analyze |
| `out` | `attack-paths-report` | Where the HTML, JSON, and comment are written |
| `comment` | `true` | Update the pull-request comment. Set `false` to keep the artifact only |

Open **Actions**, then the **Attack paths** run. The summary lists the chains. Download `attack-path-report` and open `report.html`, `graph.html`, and `threat-model.html`.

There is also a local installer: `python -m pathfinder install path\to\repository-to-scan` writes the same GitHub workflow. `--platform gitlab` writes the GitLab include. `--platform azure` writes the Azure DevOps pipeline.

## Integrate with GitLab CI

From the application repository:

```bash
curl -fsSL -o attack-paths.gitlab-ci.yml \
  https://raw.githubusercontent.com/TemTech-Solutions/attack-path-elimination/main/install/gitlab/attack-paths.gitlab-ci.yml
```

Add this to `.gitlab-ci.yml` and push:

```yaml
include:
  - local: attack-paths.gitlab-ci.yml
```

The job runs on merge requests and on the default branch. It fetches the same pinned commit from `https://github.com/TemTech-Solutions/attack-path-elimination.git`, installs dependencies after upgrading pip, and analyzes the application checkout. Artifacts are under `attack-paths-report/`: `report.html`, `graph.html`, `threat-model.html`, `graph-report.md`, `pr-comment.md`, and `graph.json`.

## Integrate with Azure DevOps

From the application repository:

```bash
mkdir -p azure-pipelines
curl -fsSL -o azure-pipelines/attack-paths.yml \
  https://raw.githubusercontent.com/TemTech-Solutions/attack-path-elimination/main/install/azure/attack-paths.yml
```

PowerShell:

```powershell
cd path\to\repository-to-scan
New-Item -ItemType Directory -Force azure-pipelines | Out-Null
Invoke-WebRequest https://raw.githubusercontent.com/TemTech-Solutions/attack-path-elimination/main/install/azure/attack-paths.yml -OutFile azure-pipelines\attack-paths.yml
```

Or `python -m pathfinder install path\to\repository-to-scan --platform azure`.

In Azure DevOps, create a pipeline from that file: **Pipelines**, **New pipeline**, select the repository, then **Existing Azure Pipelines YAML file**, and choose `azure-pipelines/attack-paths.yml`. Commit and run it.

The pipeline runs on pull requests and on pushes to `main` or `master`. It checks the application out, fetches the same pinned commit, upgrades pip, and analyzes that checkout. The artifact is `attack-path-report`, and it contains `report.html`, `graph.html`, `threat-model.html`, `graph-report.md`, `pr-comment.md`, and `graph.json`.

On an Azure Repos pull request, the pipeline updates one comment marked `<!-- pathfinder-attack-paths -->`. That comment needs the build service identity to have permission to contribute to pull requests. If the permission is missing, the artifact is still published. A repository connected from GitHub or GitLab gets the artifact. The comment step runs for Azure Repos.

The hook is `azure-pipelines/attack-paths.yml`, so it does not replace an existing `azure-pipelines.yml`. The analyzer still reads a repository's own `azure-pipelines.yml` as part of the attack graph: triggers, secrets in jobs, and deploy steps.

## Run it locally

Python 3.11 or newer. From a clone of this repository:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pathfinder analyze path/to/repository-to-scan --out out/repository-to-scan
```

PowerShell uses the same commands with backslashes. Open `out/repository-to-scan/report.html`.

| File | What it is |
| --- | --- |
| `report.html` | Ranked chains |
| `graph.html` | Diagnostic graph |
| `threat-model.html` | Grouped threat model |
| `graph-report.md` | God nodes, communities, and chains |
| `graph.json` | The snapshot, including hypotheses, reviews, and frameworks |
| `pr-comment.md` | Text you can paste onto a pull request |
| `graph.cypher` | A Neo4j import, after you review it |
| `history.json` | The earlier snapshot used to measure path erasure |

```bash
python -m pathfinder comment path/to/repository-to-scan
python -m pathfinder serve
```

`serve` listens on `http://127.0.0.1:8080`. `GET /` returns the report after a local analyze has written `out/report.html`.

`python apep.py` accepts the same subcommands as `python -m pathfinder`.

The container image runs that review service:

```bash
docker build -t attack-path-elimination .
docker run --rm -p 8080:8080 attack-path-elimination
```

## Ask a specific objective

The composed report lists the chains the catalog already knows. A hypothesis asks whether an attacker can get from one place to another under conditions you set. The walk uses edges the analyzer already proved. The result names the missing control and the edge to delete. It does not describe how to carry the walk out.

```bash
python -m pathfinder find-path path/to/repository-to-scan --from public-endpoint --to pii-database
python -m pathfinder find-path path/to/repository-to-scan --from application --to iam-admin
python -m pathfinder hunt path/to/repository-to-scan credentials
python -m pathfinder hunts
python -m pathfinder frameworks
python -m pathfinder simulate path/to/repository-to-scan rules/custom/payment-fraud.yaml
python -m pathfinder ask path/to/repository-to-scan "Show me paths where a public API could reach financial records."
python -m pathfinder query path/to/repository-to-scan "PUBLIC_ENDPOINT -[*..12]-> SECRET"
```

`ask` maps the sentence onto a start and a target on this machine. It does not send the repository anywhere.

`python -m pathfinder init` writes `rules/custom/example.yaml`. Put more files under `rules/` in the repository being scanned and the next analyze loads them.

```yaml
name: Payment Fraud
entry:
  - PUBLIC_ENDPOINT
targets:
  - PAYMENT_DB
conditions:
  - no_authz_check
  - user_input_reachable
must_not_have:
  - MFA
  - AUTHORIZATION_CHECK
severity: critical
```

## False positives the remediation team has accepted

A structural hit stays until the evidence is gone or the team records an exception. The reason must be at least 8 characters. A blank mark does not hide a finding. If `.pathfinder/exceptions.yml` cannot be read, nothing is suppressed.

```bash
python -m pathfinder except path/to/repository-to-scan \
  --rule APP05 --file admin.rb --line 2 \
  --reason "Sandbox helper, not a production entry" --by remediation
```

Or in the source, on that line or on the comment line above it:

```ruby
# pathfinder: false-positive: sandbox helper, not a production entry
system(params[:cmd])
```

Later scans omit that case from the paths, the graph, and the severity, STRIDE, DREAD, and PASTA groups. The threat model lists it under **Exceptions**, with the reason and who marked it.

## Optional: a review service and webhooks

The Action is the integration to use for a repository. A self-hosted process can analyze a local path or clone a URL, and can receive webhooks. Webhooks stay closed until a shared secret is set, so an open port cannot be used as an open clone proxy.

`POST /api/analyze` accepts a local path under the working directory, or inside `PATHFINDER_ALLOWED_ROOT`, or an `https://` URL on `github.com`, `gitlab.com`, or `dev.azure.com`. Add an enterprise host with `PATHFINDER_GIT_HOSTS` (comma-separated). The clone is stored under `data/clones` and is parsed, not executed.

| Request | Result |
| --- | --- |
| `GET /` | `report.html` after a local analyze |
| `GET /graph.html` | The graph, when that file has been written |
| `GET /api/health` | `{"status":"ok"}` |
| `GET /api/scorecard` | Scorecard for the last API analysis |
| `GET /api/paths` | Composed chains |
| `GET /api/graph` | Nodes and edges |
| `POST /api/webhooks/github` | Verifies `X-Hub-Signature-256` when `GITHUB_WEBHOOK_SECRET` is set |
| `POST /api/webhooks/gitlab` | Verifies `X-Gitlab-Token` when `GITLAB_WEBHOOK_SECRET` is set |

Pull-request comments from the service are posted only when `PATHFINDER_POST_COMMENTS=1` and `GITHUB_TOKEN` are both set. The Action posts its own comment and does not need those variables.

## Optional: Neo4j

`graph.cypher` creates one node per component and the edges the analyzer could prove. Review the file, then load it into a database you control. The HTML reports do not require Neo4j.

## Layout

- `action.yml` is the composite Action other repositories run
- `install/github/attack-paths.yml` is the workflow those repositories commit
- `install/gitlab/attack-paths.gitlab-ci.yml` is the GitLab job
- `install/azure/attack-paths.yml` is the Azure DevOps pipeline
- `pathfinder/baseline.py` is the control catalog taken from the OWASP Subtractive Hardening baseline
- `pathfinder/analyze.py` walks the repository
- `pathfinder/languages.py` and `pathfinder/platform.py` read languages and platforms that have a dedicated parser
- `pathfinder/universal.py` reads every other program, then records smaller signals
- `pathfinder/adapt.py` learns this repository's names locally
- `pathfinder/exceptions.py` applies remediation false positives
- `pathfinder/chains.py` composes stories
- `pathfinder/query.py` answers a hypothesis
- `pathfinder/rules/` holds the shipped objective templates
- `pathfinder/threatmodel.py` builds the threat-model page
- `Dockerfile` serves the local review API

The step-by-step for reading a report is in [GUIDE.md](GUIDE.md).

This graph follows the idea used by [Graphify](https://github.com/Graphify-Labs/graphify): a traversable graph and an explanation on every edge. It is not a Graphify product and it is not affiliated with Graphify Labs.

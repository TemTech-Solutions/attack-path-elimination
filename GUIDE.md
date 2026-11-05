# Step-by-step guide

This guide is how to run [TemTech-Solutions/attack-path-elimination](https://github.com/TemTech-Solutions/attack-path-elimination) and how to read the result. The product overview is in [README.md](README.md).

**The tool is built on the baseline published by the [OWASP Subtractive Hardening Top 10](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10).** Rule IDs such as APP05, C01, and S01 are control IDs from that project. The recommended change is deletion of the edge, then a constraint when the edge cannot disappear. That order is the project's hierarchy of efficacy. Path erasure rate, `P_erased / P_eligible`, is the measure that project uses. This repository applies that baseline to a repository snapshot. It is not an OWASP Foundation project, and the upstream documents remain the standard.

The scan only reads source, pipeline, and infrastructure files. It does not install the application, run its tests, or produce exploit steps. Each finding names the edge to delete or constrain.

The application you want to scan stays in its own repository. The analyzer is downloaded at job time, or run from a local clone of this repository.

## 1. Add the GitHub Action

Open a terminal in the repository you want to scan. This is not the attack-path-elimination folder.

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

From a clone of this repository you can write that file for them:

```bash
python -m pathfinder install path/to/repository-to-scan
```

Push the workflow to `main` or `master`. It also runs when a pull request is opened.

The installed job does two things. It checks out the application repository with `actions/checkout` pinned to a full commit SHA. It then runs:

```yaml
uses: TemTech-Solutions/attack-path-elimination@be1e5ddba0f48bdda8f58887d5b18bcb3dcda508
```

That value is a full commit SHA. The action refuses a branch or a tag, so a workflow that says `@main` or `@v1` fails before it analyzes anything. A push to `main` of this repository rewrites the published hook to that commit. A repository that already committed an older SHA keeps running that commit until someone copies the new hook.

The job needs `contents: read`. Pull-request comments also need `pull-requests: write`. The Action upgrades pip, installs its own requirements, analyzes `.`, uploads `attack-path-report`, writes the chains into the job summary, and on a pull request updates one comment.

To keep the artifact and skip the comment, call the action with `comment: "false"`.

## 2. Read the GitHub result

Open the repository on GitHub and go to **Actions**. Open the **Attack paths** run.

- The run summary lists the chains.
- Download the `attack-path-report` artifact.
- Open `report.html` for the ranked chains, `graph.html` for the graph, and `threat-model.html` for the grouped threat model.
- If the run came from a pull request, the same short summary is posted as one comment. Later runs update that comment. The comment is marked `<!-- pathfinder-attack-paths -->`.

The HTML files open in a browser. They do not need the Python process to stay running.

## 3. Add the GitLab job

From the application repository:

```bash
curl -fsSL -o attack-paths.gitlab-ci.yml \
  https://raw.githubusercontent.com/TemTech-Solutions/attack-path-elimination/main/install/gitlab/attack-paths.gitlab-ci.yml
```

Or `python -m pathfinder install path/to/repository-to-scan --platform gitlab`.

Add this to `.gitlab-ci.yml` and push:

```yaml
include:
  - local: attack-paths.gitlab-ci.yml
```

The job runs on merge requests and on the default branch, in a `python:3.12` image. It fetches the pinned commit from GitHub, upgrades pip, installs requirements, and analyzes the project directory. Artifacts, kept even when the job fails, are:

- `attack-paths-report/report.html`
- `attack-paths-report/graph.html`
- `attack-paths-report/threat-model.html`
- `attack-paths-report/graph-report.md`
- `attack-paths-report/pr-comment.md`
- `attack-paths-report/graph.json`

GitLab CI, like GitHub Actions and Azure Pipelines, is also something the analyzer **reads** when those files are in the repository being scanned. The install hook above is only the GitLab way to **run** the analyzer.

## 4. Scan a local checkout

Use this when you want a report on your machine. Python 3.11 or newer. From a clone of this repository:

```bash
cd attack-path-elimination
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pathfinder analyze path/to/repository-to-scan --out out/repository-to-scan
```

PowerShell:

```powershell
cd attack-path-elimination
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pathfinder analyze path\to\repository-to-scan --out out\repository-to-scan
start out\repository-to-scan\report.html
```

The command writes:

| File | What it is |
| --- | --- |
| `report.html` | Ranked chains and the scorecard |
| `graph.html` | The graph, one issue at a time |
| `threat-model.html` | Findings grouped by severity and by review framework |
| `graph.json` | Components, edges, paths, hypotheses, reviews, frameworks, and the scorecard |
| `graph-report.md` | God nodes, communities, and chains |
| `pr-comment.md` | Text you can paste onto a pull request |
| `graph.cypher` | A Neo4j import of the graph |
| `history.json` | The earlier snapshot used to measure whether chains disappeared |

`graph.json` paths are in `paths`. The scorecard is in `scorecard`. Per-component records are in `components`, each with `component`, `calls`, and `receives`.

To print the pull-request text:

```bash
python -m pathfinder comment path/to/repository-to-scan
```

To serve the latest report from `out/report.html`:

```bash
python -m pathfinder serve
```

Open `http://127.0.0.1:8080`. Stop the server with Ctrl+C.

The same service is the image built from `Dockerfile`. It listens on port 8080.

| Request | Result |
| --- | --- |
| `GET /` | The HTML report, after one local analyze has written `out/report.html` |
| `GET /graph.html` | The graph, when that file exists under the report directory |
| `GET /api/health` | `{"status":"ok"}` |
| `GET /api/scorecard` | Scorecard for the last analysis done through the API |
| `GET /api/paths` | Composed chains |
| `GET /api/graph` | Nodes and edges |

`GET /api/scorecard` answers only after `POST /api/analyze`. The path must sit inside the directory where the server was started, or inside `PATHFINDER_ALLOWED_ROOT`. A URL is accepted only for `https://github.com`, `https://gitlab.com`, and `https://dev.azure.com`. Add an enterprise host with `PATHFINDER_GIT_HOSTS` (comma-separated). The clone is stored under `data/clones` and is parsed, not executed.

## 5. Read the ranked report

Open `report.html`. The top of the page is the scorecard for that snapshot:

- **Applications** and **Components** count what was found in the repository.
- **Critical paths** counts chains scored 85 or higher.
- **Identity paths**, **Cloud paths**, and **Supply chain** count chains in those groups.
- **Attack path score** is the worst chain. Higher means a more useful path for an attacker, which is the removal queue.
- **Identity risk**, **cloud risk**, and **supply chain risk** are the worst score in each group.

The banner under the numbers is one sentence for the top chain. The left column lists every composed path, highest score first. Select one. The middle column draws that chain, and the right column shows the selected hop.

Bands are Critical at 85 and above, High at 70, Medium at 40, and Low below that.

```text
risk = exposure × privilege × asset × exploitability
```

Each factor is between 0 and 1. The score is that product on a 0–100 scale.

**What to remove** names the edge to delete, such as a request-controlled outbound fetch or a public bucket ACL. A recommendation is prefixed `Deletion` or `Constraint`. Deletion is the change to make when the edge can disappear.

Select a hop to see the risk score of the highest chain that touches that component, incoming and outgoing edge counts, what the component receives, what it calls, connected secrets, the attack paths that include it, and the evidence: rule id, title, file, and line.

Rule ids are the control IDs from the [OWASP Subtractive Hardening Top 10](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10) baseline. APP rules are the Application Hardening Top 10. C rules are the CI/CD Pipeline Subtractive Hardening Top 10. S rules are the AWS Subtractive Hardening Top 10. D rules are the Datastore Subtractive Hardening Top 10. A rules are the AI Subtractive Hardening Top 10. U rules are the Universal Subtractive Security Laws, such as a wildcard IAM policy. The wording in the report is a short recommendation for that control ID. The upstream document is the standard.

The header links to `graph.html` and `threat-model.html`.

**Show every component on a path** lists every component that sits on any chain. Select it again to return to the selected chain.

Confirm each file and line in the repository before you treat a hop as a defect.

When the repository contains both an untrusted deploy path and an application path into cloud credentials, the top of the list can include one stacked chain. That is the same two walks read as one system.

## 6. Read the graph

Open `graph.html`. The left rail is every issue, including smaller findings that are not already a full chain. Select one. The canvas lays that walk out from the entry to the last hop. The right panel is the diagnosis, each hop with its file and line, and the next deletion or constraint.

A solid edge was written in a file (`EXTRACTED`). A dashed edge was resolved across files, images, or deploy steps (`INFERRED`). Scroll to zoom and drag to pan. The path's confidence is its weakest hop.

Select a node to list every elimination path through it, the edges that make the walk reachable, and what to remove.

`graph-report.md` lists the god nodes (the components the most edges pass through), the communities, and each chain. `graph.json` is the same snapshot, including `graph.schema_version`.

## 7. Read the threat model

Open `threat-model.html`. The page starts as lenses, not as a dump of every finding.

Choose **Severity**, **Reachability**, **Exploitability**, **STRIDE**, **DREAD**, or **PASTA**. Then choose a group. If Critical says `Critical (4)`, that click lists those four findings and nothing else. Each row has:

- **Why this is first** — the band and score, whether the walk is reachable, the exploitability level, and why a single-file signature scanner would miss it
- **Effect** — the asset at risk
- **Next step** — the deletion or constraint

Select a row to open the walk: file and line, the DREAD factors used by the score, the STRIDE labels, the PASTA stage, missing controls, and an exception id you can hand to the remediation record.

**Scope** lists trust boundaries and assets. **Review notes** lists the reviewer panel. **Exceptions** lists cases the remediation team has marked as false positives. Those cases are not in the severity or framework groups.

DREAD here uses the factors already on the walk. Damage follows asset value. Affected users follows exposure. Exploitability is the existing factor. Discoverability follows a public entry. Reproducibility means the walk is present in the files, so a reviewer can find it again. It is not a statement that a request was sent.

## 8. What the scan reads

- Python, with cross-file calls from the AST
- Java, JavaScript, TypeScript, Go, C#, and PHP routes and sinks
- Every other program file, including extensionless scripts that are code, through one structural pass
- Smaller signals on all of those files: disabled certificate checks, wildcard origins, world-writable modes, debug switches, anonymous authorization exceptions, request-built redirects and file paths, weak hashes beside credentials, caller-controlled markup
- `requirements.txt` and `package.json`
- GitHub Actions, GitLab CI, and Azure Pipelines
- Dockerfiles
- Kubernetes manifests
- Terraform (`.tf`) and CloudFormation
- OpenAPI
- SQL

A local model under `.pathfinder/environment.json` learns identifier shapes this repository already confirmed and blends them into the next scan. Nothing is sent off the machine.

Directories named `.git`, `node_modules`, `venv`, `.venv`, `__pycache__`, `dist`, `build`, `out`, `data`, `.pathfinder`, and `.pytest_cache` are skipped. Files larger than 1 MB are skipped.

Python calls are resolved across files from imports. Other languages contribute routes and sinks from source patterns. If a call name is ambiguous, it is left unlinked. A bare word such as `system`, a placeholder credential, or a cache key is not a finding.

## 9. Measure a later local run

A GitHub or GitLab run is a fresh scan of that commit. Locally, the first analyze of an `--out` folder is the snapshot later runs compare against. Path erasure rate is `erased / eligible`, the Path Erasure Rate from the [OWASP Subtractive Hardening Top 10](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10) baseline, and it is 0 on that first run.

After you delete a path in code, run the same command again with the same `--out` folder. The report compares chain ids with `history.json`:

- **Erased** counts chains that were in the previous run and are absent now.
- The trend line shows the previous critical count, the current count, and the reduction.

A chain counts as gone only when its narrative changes or disappears. Renaming a function without removing the edge will usually leave the chain in place.

## 10. Record a false positive

A finding stays while the structural evidence stays. When the remediation team has reviewed a hit and it is a false positive, record it. Later scans leave it out of the paths, the graph, and the threat groups.

```bash
python -m pathfinder except path/to/repository-to-scan \
  --rule APP05 --file admin.rb --line 2 \
  --reason "Sandbox helper, not a production entry" --by remediation
```

That writes `.pathfinder/exceptions.yml` in the repository being scanned. Use the file and line from the report. The reason must be at least 8 characters.

The same mark can sit on the line, or on the comment line directly above it:

```ruby
# pathfinder: false-positive: sandbox helper, not a production entry
system(params[:cmd])
```

`python -m pathfinder exceptions path/to/repository-to-scan` lists what is recorded. A blank reason does not suppress a finding. If the exceptions file is unreadable, the scan keeps every finding and reports the file error.

In `threat-model.html`, open **Exceptions** to see the reason and who marked the case.

## 11. Ask whether a specific objective is reachable

The composed report answers "which chains does this catalog already know?" A hypothesis answers "can an attacker reach the objective I care about?"

```bash
python -m pathfinder find-path path/to/repository-to-scan --from public-endpoint --to pii-database
python -m pathfinder find-path path/to/repository-to-scan --from application --to iam-admin
python -m pathfinder find-path path/to/repository-to-scan --from internet --to secret
python -m pathfinder hunt path/to/repository-to-scan credentials
python -m pathfinder hunt path/to/repository-to-scan ransomware
python -m pathfinder simulate path/to/repository-to-scan rules/custom/payment-fraud.yaml
python -m pathfinder ask path/to/repository-to-scan "Show me paths where a public API could reach financial records."
python -m pathfinder query path/to/repository-to-scan "PUBLIC_ENDPOINT -[*..12]-> SECRET"
```

`python apep.py` accepts the same subcommands. `python -m pathfinder hunts` lists the templates. `python -m pathfinder frameworks` lists the models applied to every scan.

Shipped templates cover credential exposure, secret exposure, AWS privilege escalation, privilege escalation into an admin function, lateral movement into a datastore, ransomware blast radius, PCI data, personal data, payment fraud, an unprotected admin path, production, source code, supply chain, and OWASP web, API, and LLM objectives.

`python -m pathfinder init` writes `rules/custom/example.yaml`. The file names the entry, the targets, conditions such as `no_authz_check` and `user_input_reachable`, and controls that must be absent (`MFA`, `AUTHORIZATION_CHECK`). `simulate` runs that file. Put more files under `rules/` in the repository being scanned and the next analyze picks them up.

The output is the walk, the risk band, the missing controls, and the edge to delete or constrain. The question command maps the sentence onto a start and a target on this machine. It does not send the repository to a model.

## 12. Optional: a webhook on your own server

The GitHub Action is the hook to use for a repository. A self-hosted webhook stays closed until you set a secret, so an open port cannot clone arbitrary repositories.

```bash
export GITHUB_WEBHOOK_SECRET="a long random string"
python -m pathfinder serve
```

Point a GitHub webhook at `POST /api/webhooks/github` and set the same secret. The service checks `X-Hub-Signature-256`. To also comment on the pull request from this process, set `GITHUB_TOKEN` and `PATHFINDER_POST_COMMENTS=1`. The Action does not use those variables. It comments with the workflow token.

GitLab uses `GITLAB_WEBHOOK_SECRET` and the header `X-Gitlab-Token`, posted to `/api/webhooks/gitlab`.

## 13. Optional: Neo4j

`graph.cypher` in the local output creates one node per component and the edges the analyzer could prove (`CALLS`, `ROUTES_TO`, `READS`, `FLOWS_TO`, `USES_SECRET`, `DEPLOYS`, `INVOKES`, `TRUSTS`). Review the file, then load it into a database you control. The HTML reports do not require Neo4j.

## 14. What a result is, and what it is not

A chain means the files contain a connected walk from an entry to a valuable target.

Confirm the file and line before you treat a hop as a defect. Python uses the AST. The languages with a dedicated parser contribute routes and sinks from source patterns. Every other program is read by the structural pass. A local model learns names this repository already confirmed and carries them to the next scan.

A score ranks removal order inside this snapshot. It is not a CVSS score, and it is not proof that a specific request would succeed. The control behind each finding is the [OWASP Subtractive Hardening Top 10](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10) baseline: delete the edge, or constrain it when it cannot be deleted. Other framework tags, including OWASP Top 10 and STRIDE, are a way to read the same walk. They are not a certification, and this repository is not an OWASP Foundation project.

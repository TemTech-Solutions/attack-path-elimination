# Step-by-step guide

Use this platform by adding one workflow to the repository you want to scan. GitHub checks that repository out and downloads the analyzer from the public platform repository [vekis11/attack-path-elimination_POC](https://github.com/vekis11/attack-path-elimination_POC). The application stays in its own repository.

The scan only reads source, pipeline, and infrastructure files. It does not install the application, run its tests, or produce exploit steps. Each finding tells you which path to remove.

Commands below are for PowerShell.

## 1. Hook the repository you want to scan

Open a terminal in that repository. This is not the platform folder.

```powershell
cd D:\src\your-test-repo
New-Item -ItemType Directory -Force .github\workflows | Out-Null
Invoke-WebRequest https://raw.githubusercontent.com/vekis11/attack-path-elimination_POC/main/install/github/attack-paths.yml -OutFile .github\workflows\attack-paths.yml
git add .github\workflows\attack-paths.yml
git commit -m "Add attack path scan"
git push
```

Push that commit to `main` or `master`. The workflow also runs when you open a pull request.

The workflow file checks out the application repository, then runs:

```yaml
uses: vekis11/attack-path-elimination_POC@main
```

## 2. Read the result

Open the repository on GitHub and go to **Actions**. Open the **Attack paths** run.

- The run summary lists the chains.
- Download the `attack-path-report` artifact and open `report.html`.
- If the run came from a pull request, the same summary is posted as one comment. Later runs update that comment.

The report is one HTML file. You can download it and open it without leaving the Python service running.

## 3. Read the report

The top of the page is the scorecard for that snapshot:

- **Applications** and **Components** count what was found in the repository.
- **Critical paths** counts chains scored 85 or higher.
- **Identity paths**, **Cloud paths**, and **Supply chain** count chains in those groups.
- **Attack path score** is the worst chain. Higher means a more useful path for an attacker.
- **Identity risk**, **cloud risk**, and **supply chain risk** are the worst score in each group.

The banner under the numbers is one sentence for the top chain. Separate scanners would file each weak check on its own. This report keeps a connected walk together, for example a public route, an auth gap, an outbound fetch, cloud credentials, and a data store.

The left column lists every composed path, highest score first. Click one. The middle column draws that chain from top to bottom, and the right column shows the selected hop.

Bands are Critical at 85 and above, High at 70, Medium at 40, and Low below that.

The four numbers under the chain are the formula:

```text
risk = exposure × privilege × asset × exploitability
```

Each factor is between 0 and 1. The score is that product on a 0–100 scale.

**What to remove** names the edge to delete, such as a request-controlled outbound fetch or a public bucket ACL.

Click a hop to see:

- **Risk score**, the highest chain that touches that component
- **Incoming** and **Outgoing** edge counts
- **Receives**, such as `POST /api/payment`
- **Calls**, the functions this component calls
- **Connected secrets**
- **Attack paths** that include this component
- **Evidence**, the rule id and title, with file and line

Rule ids follow the OWASP Subtractive Hardening baseline. APP rules are application paths. C rules are pipeline paths. U rules are universal, such as a wildcard IAM policy.

Confirm each file and line in the repository before you treat a hop as a defect. Then delete or constrain the path. A new alert does not erase it.

The button **Show every component on a path** lists every component that sits on any chain. Click it again to return to the selected chain.

## 4. What the scan reads

- Python, JavaScript, TypeScript, Java, Go, C#, and PHP source
- `requirements.txt` and `package.json`
- GitHub Actions, GitLab CI, and Azure Pipelines files
- Dockerfiles
- Kubernetes manifests
- Terraform (`.tf`)
- OpenAPI files

Directories named `.git`, `node_modules`, `venv`, `dist`, and `build` are skipped. Files larger than 1 MB are skipped.

Python calls are resolved across files from imports. The other languages contribute routes and dangerous calls from source patterns. If a call name is ambiguous, it is left unlinked.

`graph.json` in the artifact is the machine-readable copy of the page. Paths are in `paths`. The scorecard is in `scorecard`. Per-component records are in `components`, each with `component`, `calls`, and `receives`.

## 5. GitLab

From the application repository:

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/vekis11/attack-path-elimination_POC/main/install/gitlab/attack-paths.gitlab-ci.yml -OutFile attack-paths.gitlab-ci.yml
```

Add this to that repository's `.gitlab-ci.yml` and push:

```yaml
include:
  - local: attack-paths.gitlab-ci.yml
```

The job clones `https://github.com/vekis11/attack-path-elimination_POC.git` and analyzes the application checkout. The HTML report is a job artifact under `attack-paths-report/`.

## 6. Scan a local checkout

Use this when you want a report on your machine before the GitHub run finishes. From a clone of this platform:

```powershell
cd C:\Users\vekis\Desktop\CICD\attack-path-elimination_POC
pip install -r requirements.txt
python -m pathfinder analyze D:\src\your-test-repo --out out\your-test-repo
start out\your-test-repo\report.html
```

`python --version` should be 3.11 or newer. The command writes:

| File | What it is |
| --- | --- |
| `report.html` | The report you open in a browser |
| `graph.json` | Components, edges, paths, and the scorecard |
| `pr-comment.md` | Text you can paste onto a pull request |
| `graph.cypher` | A Neo4j import of the graph |
| `history.json` | The baseline used later to measure whether chains disappeared |

To print the pull-request text:

```powershell
python -m pathfinder comment D:\src\your-test-repo
```

To serve the latest report:

```powershell
python -m pathfinder serve
```

Open `http://127.0.0.1:8080`. Stop the server with Ctrl+C.

| Request | Result |
| --- | --- |
| `GET /` | The HTML report, after one local analyze has written `out\report.html` |
| `GET /api/health` | `{"status":"ok"}` |
| `GET /api/scorecard` | Scorecard for the last analysis done through the API |
| `GET /api/paths` | Composed chains |
| `GET /api/graph` | Nodes and edges |

`GET /api/scorecard` answers only after `POST /api/analyze`. The path must sit inside the directory where the server was started, or inside `PATHFINDER_ALLOWED_ROOT`. A URL is accepted only for `https://github.com`, `https://gitlab.com`, and `https://dev.azure.com`. Add an enterprise host with `PATHFINDER_GIT_HOSTS` (comma-separated). The clone is stored under `data\clones` and is parsed, not executed.

## 7. Measure a later run

A GitHub run is a fresh scan of that commit. Locally, the first analyze of an `--out` folder is the baseline. Path erasure rate is `erased / eligible`, and it is 0 on that first run.

After you delete a path in code, run the same local command again with the same `--out` folder. The report compares chain ids with `history.json`:

- **Erased** counts chains that were in the previous run and are absent now.
- The trend line shows the previous critical count, the current count, and the reduction.

A chain counts as gone only when its narrative changes or disappears. Renaming a function without removing the edge will usually leave the chain in place.

## 8. Optional: a webhook on your own server

The GitHub Action is the hook to use for a repository. A self-hosted webhook stays closed until you set a secret, so an open port cannot clone arbitrary repositories.

```powershell
$env:GITHUB_WEBHOOK_SECRET = "a long random string"
python -m pathfinder serve
```

Point a GitHub webhook at `POST /api/webhooks/github` and set the same secret. The service checks `X-Hub-Signature-256`. To also comment on the pull request, set `GITHUB_TOKEN` and `PATHFINDER_POST_COMMENTS=1`.

GitLab uses `GITLAB_WEBHOOK_SECRET` and the header `X-Gitlab-Token`, posted to `/api/webhooks/gitlab`.

## 9. Optional: Neo4j

`graph.cypher` in the local output creates one node per component and the edges the analyzer could prove (`CALLS`, `ROUTES_TO`, `READS`, `FLOWS_TO`, `USES_SECRET`, `DEPLOYS`, `INVOKES`). Review the file, then load it into a database you control. The HTML report does not require Neo4j.

## Baseline the report uses

Findings are tagged with a control from the [OWASP Subtractive Hardening Top 10](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10). The scorecard counts them by family:

| Family | IDs | What this scan looks for |
| --- | --- | --- |
| Application | APP01–APP10 | Open routes, raw request bodies, tokens, dynamic execution, egress, query construction, weak authority |
| CI/CD | C01–C10 | Secrets in jobs, privileged runners, floating dependencies and actions, untrusted triggers, unsigned deploys |
| AWS | S01–S10 | Tokenless metadata, wildcard trust, public control planes, open security groups, public data stores |
| Datastore | D01–D10 | Host execution, linked databases, `GRANT ALL`, database file export |
| AI | A01–A10 | Executable model loads, agent shell or network tools, uncapped loops, unfiltered retrieval |
| Universal | U01–U10 | Static credentials, open egress, wildcard privilege |

A recommendation is prefixed `Deletion` or `Constraint`. Deletion is the change to make when the edge can disappear. The report does not ask you to add a detector.

When the repository contains both an untrusted deploy path and an application path into cloud credentials, the top of the list includes one stacked chain. That is the same two walks read as one system, which is how the baseline treats layered risk.

## Read the graph

`graph.html` sits next to `report.html` in the artifact and in the local `--out` folder. Open it in a browser. Communities are colors. A solid edge was written in a file (`EXTRACTED`). A dashed edge was resolved across files, images, or deploy steps (`INFERRED`). Click a node for its source line, its community, its degree, and every connection. The path menu highlights one chain. That chain's confidence is its weakest hop.

`graph-report.md` lists the god nodes (the components the most edges pass through), the communities, and each chain with those hops. `graph.json` is the same snapshot, including `graph.schema_version`.

This map follows the knowledge-graph idea used by [Graphify](https://github.com/Graphify-Labs/graphify): a traversable graph, every edge explained, no vector store. It is not a Graphify product and it is not affiliated with Graphify Labs.

## What a result is, and what it is not

A chain means the files contain a connected walk from an entry to a valuable target: a public route, an untrusted pipeline, or a public bucket, through calls and deploy edges, to credentials, data, or a production workload.

Confirm the file and line before you treat a hop as a defect. Pattern matches on Java, JavaScript, Go, C#, and PHP are narrower than the Python AST. A score ranks removal order inside this snapshot. It is not a CVSS score, and it is not proof that a specific request would succeed.

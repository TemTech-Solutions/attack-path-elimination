# Attack path elimination

Hook a repository by adding one workflow. GitHub checks that repository out and downloads the analyzer from this public repository. The application is not copied here.

From the repository you want to scan:

```powershell
cd D:\src\your-test-repo
New-Item -ItemType Directory -Force .github\workflows | Out-Null
Invoke-WebRequest https://raw.githubusercontent.com/vekis11/attack-path-elimination_POC/main/install/github/attack-paths.yml -OutFile .github\workflows\attack-paths.yml
git add .github\workflows\attack-paths.yml
git commit -m "Add attack path scan"
git push
```

Push to `main` or `master`, or open a pull request. The **Attack paths** Action run lists the chains, and the `attack-path-report` artifact contains `report.html`. The step-by-step is in [GUIDE.md](GUIDE.md).

The scan connects application code, CI, containers, Kubernetes, Terraform, and OpenAPI into one graph, then reports the chains an attacker could walk. A scanner that emits each weak check separately is not the same thing as one sentence that follows the walk from a public entry to a crown jewel.

The control catalog follows the [OWASP Subtractive Hardening Top 10](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10): Application (APP01–APP10), CI/CD (C01–C10), AWS (S01–S10), Datastore (D01–D10), AI (A01–A10), and the Universal laws (U01–U10). Each finding names the edge to delete or constrain. Deletion ranks ahead of constraint. The tool does not run the repository and does not produce exploit procedures.

Path risk is `exposure × privilege × asset × exploitability`, scaled to 0–100. Path erasure rate is `P_erased / P_eligible`. The first local run is the baseline (rate 0). A later run counts a chain as erased when it is gone.

## Local scan

From a clone of this platform, point the analyzer at the other repository:

```powershell
pip install -r requirements.txt
python -m pathfinder analyze D:\src\your-test-repo --out out\your-test-repo
python -m pathfinder comment D:\src\your-test-repo
python -m pathfinder serve
```

`GET /` serves the report after a local analyze. `POST /api/analyze` accepts a local path under the working directory, or an `https://github.com/...`, GitLab, or Azure DevOps URL. Webhooks stay closed until `GITHUB_WEBHOOK_SECRET` or `GITLAB_WEBHOOK_SECRET` is set. Comments are posted to GitHub only when `PATHFINDER_POST_COMMENTS=1` and `GITHUB_TOKEN` are both set.

## What the graph contains

Python is parsed with the standard AST, including cross-file calls. Java, JavaScript/TypeScript, Go, C#, and PHP contribute routes and sinks from source patterns. Workflows, Dockerfiles, Kubernetes manifests, Terraform, CloudFormation, SQL, dependency manifests, and OpenAPI contribute the surrounding edges: `CALLS`, `ROUTES_TO`, `READS`, `FLOWS_TO`, `USES_SECRET`, `DEPLOYS`, `INVOKES`, `TRUSTS`. When a supply-chain path and an application cloud path both exist, the report also states them as one stack.

That is structural composition, not a whole-program compiler. Ambiguous calls are left unlinked rather than guessed. `graph.html` draws the same graph: communities as colors, `EXTRACTED` edges that were written in a file, and `INFERRED` edges the analyzer resolved. A path's confidence is its weakest hop. The idea matches a code knowledge graph such as [Graphify](https://github.com/Graphify-Labs/graphify). This project is not affiliated with Graphify Labs.

## Layout

- `action.yml` is the Action other repositories run
- `install/github/attack-paths.yml` is the workflow those repositories commit
- `pathfinder/analyze.py` walks the repository
- `pathfinder/languages.py` and `pathfinder/platform.py` build components
- `pathfinder/chains.py` composes stories
- `pathfinder/scoring.py` ranks them
- `pathfinder/templates/report.html` is the external view

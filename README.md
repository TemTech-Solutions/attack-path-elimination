# Attack path elimination

Hook a repository by adding one workflow. GitHub checks that repository out and downloads the analyzer from [TemTech-Solutions/attack-path-elimination](https://github.com/TemTech-Solutions/attack-path-elimination). The application is not copied into that repository.

From the repository you want to scan:

```powershell
cd path\to\repository-to-scan
New-Item -ItemType Directory -Force .github\workflows | Out-Null
Invoke-WebRequest https://raw.githubusercontent.com/TemTech-Solutions/attack-path-elimination/main/install/github/attack-paths.yml -OutFile .github\workflows\attack-paths.yml
git add .github\workflows\attack-paths.yml
git commit -m "Add attack path scan"
git push
```

Push to `main` or `master`, or open a pull request. The **Attack paths** Action run lists the chains, and the `attack-path-report` artifact contains `report.html`. The step-by-step is in [GUIDE.md](GUIDE.md).

The scan connects application code, CI, containers, Kubernetes, Terraform, and OpenAPI into one graph, then reports the chains an attacker could walk. A scanner that emits each weak check separately is not the same thing as one sentence that follows the walk from a public entry to a crown jewel.

The control catalog follows the [OWASP Subtractive Hardening Top 10](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10): Application (APP01–APP10), CI/CD (C01–C10), AWS (S01–S10), Datastore (D01–D10), AI (A01–A10), and the Universal laws (U01–U10). Each finding names the edge to delete or constrain. Deletion ranks ahead of constraint. The tool does not run the repository and does not produce exploit procedures.

Path risk is `exposure × privilege × asset × exploitability`, scaled to 0–100. Path erasure rate is `P_erased / P_eligible`. The first local run is the baseline (rate 0). A later run counts a chain as erased when it is gone.

## Local scan

From a clone of [TemTech-Solutions/attack-path-elimination](https://github.com/TemTech-Solutions/attack-path-elimination), point the analyzer at the other repository:

```powershell
cd attack-path-elimination
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pathfinder analyze path\to\repository-to-scan --out out\repository-to-scan
python -m pathfinder comment path\to\repository-to-scan
python -m pathfinder serve
```

`GET /` serves the report after a local analyze. `POST /api/analyze` accepts a local path under the working directory, or an `https://github.com/...`, GitLab, or Azure DevOps URL. Webhooks stay closed until `GITHUB_WEBHOOK_SECRET` or `GITLAB_WEBHOOK_SECRET` is set. Comments are posted to GitHub only when `PATHFINDER_POST_COMMENTS=1` and `GITHUB_TOKEN` are both set.

## Ask whether a specific objective is reachable

The composed report lists the chains the catalog already knows. A hypothesis asks whether an attacker can get from one place to another, under conditions you set. The walk uses edges the analyzer proved. Each result names the missing control and the edge to delete. It does not describe how to carry the walk out.

```powershell
python -m pathfinder find-path path\to\repository-to-scan --from public-endpoint --to pii-database
python -m pathfinder find-path path\to\repository-to-scan --from application --to iam-admin
python -m pathfinder find-path path\to\repository-to-scan --from internet --to secret
python -m pathfinder hunt path\to\repository-to-scan credentials
python -m pathfinder hunt path\to\repository-to-scan privilege-escalation
python -m pathfinder simulate path\to\repository-to-scan rules\custom\payment-fraud.yaml
python -m pathfinder ask path\to\repository-to-scan "Show me paths where a public API could reach financial records."
python -m pathfinder query path\to\repository-to-scan "PUBLIC_ENDPOINT -[*..12]-> SECRET"
```

`python apep.py` is the same command. `hunt` with no name runs the shipped templates. `init` writes `rules/custom/example.yaml`. A repository can keep its own hypotheses in `rules/`.

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

Every scan runs those templates and a panel of reviewers. The reviewers map walks onto OWASP Top 10, API Security Top 10, ASVS, CI/CD, Kubernetes, Docker, Serverless, LLM, and Subtractive Hardening, plus STRIDE, DREAD, PASTA, LINDDUN, OCTAVE, Trike, VAST, attack trees, MITRE ATT&CK tactics, and the Lockheed Martin Kill Chain. MITRE is recorded as a tactic name only. `graph.json` includes `hypotheses`, `agent_reviews`, and `frameworks`.

## What the graph contains

Python is parsed with the standard AST, including cross-file calls. Java, JavaScript/TypeScript, Go, C#, and PHP contribute routes and sinks from source patterns. Every other program file is read by the same structural pass: routes, calls, queries, outbound requests, credentials, and the smaller signals around them. A local centroid model learns this repository's identifier shapes and blends them into the next scan of that environment. No source is sent off the machine. Workflows, Dockerfiles, Kubernetes manifests, Terraform, CloudFormation, SQL, dependency manifests, and OpenAPI contribute the surrounding edges: `CALLS`, `ROUTES_TO`, `READS`, `FLOWS_TO`, `USES_SECRET`, `DEPLOYS`, `INVOKES`, `TRUSTS`. When a supply-chain path and an application cloud path both exist, the report also states them as one stack.

That is structural composition, not a whole-program compiler. Ambiguous calls are left unlinked rather than guessed. `graph.html` draws the same graph. Select an issue and the clear path is laid out left to right, with the diagnosis, the file and line of each hop, and the next deletion or constraint. `EXTRACTED` edges were written in a file. `INFERRED` edges were resolved. A path's confidence is its weakest hop. The idea matches a code knowledge graph such as [Graphify](https://github.com/Graphify-Labs/graphify). This project is not affiliated with Graphify Labs.

## Layout

- `action.yml` is the Action other repositories run
- `install/github/attack-paths.yml` is the workflow those repositories commit
- `pathfinder/analyze.py` walks the repository
- `pathfinder/languages.py` and `pathfinder/platform.py` build components for the languages with a dedicated parser
- `pathfinder/universal.py` reads every other program, then a second pass records smaller signals in all of them
- `pathfinder/adapt.py` learns this repository's names locally and reuses them on the next scan
- `pathfinder/chains.py` composes stories
- `pathfinder/query.py` answers a hypothesis against that graph
- `pathfinder/rules/` holds the shipped hunt templates
- `pathfinder/scoring.py` ranks them
- `pathfinder/templates/report.html` is the external view

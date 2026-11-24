# Step-by-step guide

[README.md](README.md) answers what [TemTech-Solutions/attack-path-elimination](https://github.com/TemTech-Solutions/attack-path-elimination) is for. This guide answers the next questions a team asks once they decide to run it: where the result shows up, how to read each page, and how to accept one false positive without hiding the rest of the file.

**The tool is built on the baseline published by the [OWASP Subtractive Hardening Top 10](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10).** Rule IDs such as APP05, C01, and S01 are control IDs from that project. The recommended change is deletion of the edge, then a constraint when the edge cannot disappear. That order is the project's hierarchy of efficacy. Path erasure rate, `P_erased / P_eligible`, is the measure that project uses. This repository applies that baseline to a repository snapshot. It is not an OWASP Foundation project, and the upstream documents remain the standard.

The scan only reads source, pipeline, and infrastructure files. It does not install the application, run its tests, or produce exploit steps. Each finding names the edge to delete or constrain.

The application you want to scan stays in its own repository. The analyzer is downloaded at job time, or run from a local clone of this repository.

## 1. How do I add this to GitHub?

**Easy install and testing:** open [TemTech Attack Path](https://github.com/apps/temtech-attack-path) and install the GitHub App. Sign in as the account that owns the repositories, then choose **All repositories** or **Only select repositories**. Use that page to try the app on the repositories you pick. The private key stays with the app owner.

To run the scan from the repository itself, add this workflow on the target branch. The target branch is the branch pull requests merge into.

1. Open the repository you want to scan. This is not the attack-path-elimination folder.
2. Check out the target branch.
3. Save the workflow as `.github/workflows/attack-paths.yml`.
4. Commit that file and push the target branch.

GitHub reads the workflow from the target branch. A pull request into that branch runs the scan after the file is on the target branch. A push runs the scan on every branch that contains the file.

```yaml
# Installed from https://github.com/vekis11/attack-path-elimination_POC
name: Attack paths

on:
  pull_request:

  push:

permissions:
  contents: read
  pull-requests: write

jobs:
  attack-paths:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout this repository
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0

      - name: Attack path elimination
        uses: TemTech-Solutions/attack-path-elimination@5d9859c2fe7c0686d058277bea257a362fc26e0d
```

The same file is `install/github/repository-workflow.yml`. The report shows it under **Add this scan to a repository**, in **GitHub on the target branch**.

The two-job workflow below is the other GitHub file. It checks the findings again and fails the job when a critical path remains.

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

The installed workflow has two jobs. `attack-paths` checks out the application repository with `actions/checkout` pinned to a full commit SHA, then runs the deep scan. `exception-scan` runs that deep scan again, keeps only findings this checkout confirmed, and drops every recorded exception from the published findings. Each job then runs **Scan summary**, which prints the high-level result before checkout's post step. The `uses:` line must be a release tag or a full 40-character commit SHA. `@main` and `@master` stop the job before the scan starts.

Before you add or update that line, open the [Marketplace listing](https://github.com/marketplace/actions/attack-path-elimination) and confirm the latest release shown there. Use that release. A tag or hash copied from an older page stays on the older release until you change the workflow.

**Release tag.** Copy the latest release tag from that Marketplace page onto the `uses` line. Check the page again each time you update the workflow, and use the latest release it shows.

**Pinned SHA.** You can pin the same line to the full 40-character commit hash of the release you just verified. A short hash does not run. Copy the hash from that Marketplace release. A later commit on `main` leaves a pinned line on the same hash until you replace it. The workflow file from this repository is pinned to a full commit hash. Confirm on Marketplace that it still matches the latest release before you rely on it.

The jobs need `contents: read`. Pull-request comments also need `pull-requests: write`. The Action upgrades pip, installs its own requirements, and analyzes `.`. The deep scan uploads `attack-path-review` and does not comment. The exception scan uploads `attack-path-report`, writes the high-level summary into the job summary, and on a pull request updates one comment with the longer work queue. It then fails the job when critical paths remain. Recorded exceptions are applied first, so an accepted exception can let the job pass. Require the **Attack paths** workflow in branch protection to block the merge. To also fail on high paths, set `max_high: "0"` on that job. A local run uses the same rule: `python -m pathfinder analyze . --exception-scan --max-critical 0`.

To keep the artifact and skip the comment, call the action with `comment: "false"`.

## 2. What do I read in the pipeline?

Read the summary before the HTML. Open the repository on GitHub and go to **Actions**. Open the **Attack paths** run, then the `exception-scan` job.

- **Scan summary** is the step after the attack-path action and before **Post Checkout this repository**. It says what was found: critical, high, and medium path counts, findings that stayed, unused private symbols that can be removed, and the first path in one sentence. **Exceptions skipped** is the number of findings left out because a recorded exception matched them. The job summary panel shows the same text. `summary.md` in the artifact is that text.
- Download the `attack-path-report` artifact from `exception-scan` for the detail. `attack-paths` uploads `attack-path-review` from the scan before exceptions are applied.
- Open `report.html` for the ranked chains and unused code, `graph.html` for the graph, and `threat-model.html` for the grouped threat model. Open a finding for the file, the line, how an attacker can use it, and the exception record.
- Critical and high walks are also file annotations on the run. A recorded exception removes that one issue from the attack paths and from the threat model. The local learner holds back a learned name when it matches false positives this repository already accepted. A finding without a confirmed file, line, and evidence is not published.
- If the run came from a pull request, the work queue is posted as one comment. Later runs update that comment. The comment is marked `<!-- pathfinder-attack-paths -->`. The comment is the queue. The scan summary is the count.

The HTML files open in a browser. They do not need the Python process to stay running.

## 3. How do I add this to GitLab?

Check out the target branch in the repository you want to scan. The target branch is the branch merge requests merge into.

1. Save the workflow below as `attack-paths.gitlab-ci.yml`.
2. On that same branch, add this to `.gitlab-ci.yml`:

```yaml
include:
  - local: attack-paths.gitlab-ci.yml
```

3. Commit both files and push the target branch.

A merge request into that branch runs the scan after both files are on the target branch. A push runs the scan on every branch that contains the file. The same text is `install/gitlab/repository-workflow.gitlab-ci.yml`.

```yaml
# Installed from https://github.com/vekis11/attack-path-elimination_POC
# Save this file as attack-paths.gitlab-ci.yml on the target branch.
# Add this to .gitlab-ci.yml on that same branch:
# include:
#   - local: attack-paths.gitlab-ci.yml
attack-paths:
  image: python:3.12
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH
  script:
    - git init "$CI_PROJECT_DIR/.pathfinder-tool"
    - git -C "$CI_PROJECT_DIR/.pathfinder-tool" remote add origin https://github.com/TemTech-Solutions/attack-path-elimination.git
    - git -C "$CI_PROJECT_DIR/.pathfinder-tool" fetch --depth 1 origin 5d9859c2fe7c0686d058277bea257a362fc26e0d
    - git -C "$CI_PROJECT_DIR/.pathfinder-tool" checkout --detach FETCH_HEAD
    - python -m pip install --upgrade pip
    - python -m pip install -r "$CI_PROJECT_DIR/.pathfinder-tool/requirements.txt"
    - PYTHONUNBUFFERED=1 PYTHONPATH="$CI_PROJECT_DIR/.pathfinder-tool" python -m pathfinder analyze . --out attack-paths-report
  artifacts:
    when: always
    paths:
      - attack-paths-report/
```

The file further down is the other GitLab job. It checks the findings again and fails the job when a critical path remains.

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

The job runs on merge requests and on the default branch, in a `python:3.12` image. It fetches the full commit hash pinned in that file from GitHub, upgrades pip, installs requirements, and lists every file and component in the log. The log then prints `summary.md`. GitLab and Azure hooks stay on that hash. The release-tag option in section 1 is for the GitHub Action `uses:` line. Artifacts, kept even when the job fails, are:

- `attack-paths-report/report.html`
- `attack-paths-report/graph.html`
- `attack-paths-report/threat-model.html`
- `attack-paths-report/graph-report.md`
- `attack-paths-report/pr-comment.md`
- `attack-paths-report/summary.md`
- `attack-paths-report/graph.json`

GitLab CI, GitHub Actions, and Azure Pipelines are also files the analyzer reads when they are in the repository being scanned. The hook above is how GitLab runs the analyzer.

## 4. How do I add this to Azure DevOps?

Check out the target branch in the repository you want to scan. The target branch is the branch pull requests merge into.

1. Save the workflow below as `azure-pipelines/attack-paths.yml`.
2. Commit that file and push the target branch.
3. In Azure DevOps, open **Pipelines**, **New pipeline**, **Existing Azure Pipelines YAML file**, and choose `azure-pipelines/attack-paths.yml`.

A pull request into that branch runs the scan after the file is on the target branch. A push runs the scan on every branch that contains the file. The same text is `install/azure/repository-workflow.yml`.

```yaml
# Installed from https://github.com/vekis11/attack-path-elimination_POC
# Save this file as azure-pipelines/attack-paths.yml on the target branch.
trigger:
  branches:
    include:
      - "*"

pr:
  branches:
    include:
      - "*"

pool:
  vmImage: ubuntu-latest

steps:
  - checkout: self
    fetchDepth: 1

  - task: UsePythonVersion@0
    displayName: Use Python 3.12
    inputs:
      versionSpec: "3.12"

  - bash: |
      set -euo pipefail
      TOOL="$(Agent.TempDirectory)/pathfinder-tool"
      git init "$TOOL"
      git -C "$TOOL" remote add origin https://github.com/TemTech-Solutions/attack-path-elimination.git
      git -C "$TOOL" fetch --depth 1 origin 5d9859c2fe7c0686d058277bea257a362fc26e0d
      git -C "$TOOL" checkout --detach FETCH_HEAD
      python -m pip install --upgrade pip
      python -m pip install -r "$TOOL/requirements.txt"
      PYTHONUNBUFFERED=1 PYTHONPATH="$TOOL" python -m pathfinder analyze "$(Build.SourcesDirectory)" --out "$(Build.ArtifactStagingDirectory)/attack-paths-report"
    displayName: Attack path elimination

  - task: PublishPipelineArtifact@1
    condition: succeededOrFailed()
    displayName: Publish attack path report
    inputs:
      targetPath: $(Build.ArtifactStagingDirectory)/attack-paths-report
      artifact: attack-path-report
```

The file further down is the other Azure pipeline. It checks the findings again and fails the job when a critical path remains.

From the application repository:

```bash
mkdir -p azure-pipelines
curl -fsSL -o azure-pipelines/attack-paths.yml \
  https://raw.githubusercontent.com/TemTech-Solutions/attack-path-elimination/main/install/azure/attack-paths.yml
```

Or `python -m pathfinder install path/to/repository-to-scan --platform azure`.

In Azure DevOps, open **Pipelines**, **New pipeline**, select the repository, choose **Existing Azure Pipelines YAML file**, and set the path to `azure-pipelines/attack-paths.yml`.

The pipeline runs on pull requests and on `main` or `master`, on `ubuntu-latest`, with Python 3.12. It fetches the full commit hash pinned in that file from GitHub, upgrades pip, installs requirements, and lists every file and component in the log. The log then prints `summary.md`. The artifact `attack-path-report` is published even when a later step fails, and it contains:

- `summary.md`
- `report.html`
- `graph.html`
- `threat-model.html`
- `graph-report.md`
- `pr-comment.md`
- `graph.json`

On an Azure Repos pull request, the pipeline updates one comment marked `<!-- pathfinder-attack-paths -->` when the build service can contribute to pull requests. The artifact is published either way. A GitHub or GitLab repository built by Azure Pipelines gets the artifact. The comment step is for Azure Repos.

This file does not replace an existing `azure-pipelines.yml`. A repository's own `azure-pipelines.yml` is still read into the attack graph.

## 5. How do I scan a checkout on my machine?

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
| `summary.md` | What was found, and how many exceptions were skipped |
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

## 6. How do I read the ranked report?

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

The header links to `graph.html`, `threat-model.html`, and the unused-code section.

**Start here** is the action list. Each row is one change: a critical or high path, or a file that has unused symbols. Select a row to jump to that path or to the unused-code section. The path list leads with **Action** and the first recommendation.

**Findings on this path** is one card per detection. File, rule, and line stay visible. Open a card for the record:

- How an attacker can use this finding, on this component or by moving into another component in the repository or on the infrastructure the walk reaches
- The **effect** and the **next step**, which names the exact line to change
- DREAD, STRIDE, PASTA, the exception id, and the walk
- **For the exception record**, the `pathfinder-exceptions.yml` snippet, Copy, and the inline `# pathfinder: false-positive:` mark

**Unused code in this repository** groups removals by file. A private symbol is listed when no public function, import, decorator, or module-level call can reach it, including through other private helpers. Each card says what was found, how it affects the repository, how the scan knows, and the next step, with a few numbered source lines. Public symbols that nothing here calls are listed under **Leave in place** and are not recommended for deletion.

**Show every component on a path** lists every component that sits on any chain. Select it again to return to the selected chain.

Confirm each file and line in the repository before you treat a hop as a defect.

When the repository contains both an untrusted deploy path and an application path into cloud credentials, the top of the list can include one stacked chain. That is the same two walks read as one system.

## 7. How do I read the graph?

Open `graph.html`. The left rail is every issue, including smaller findings that are not already a full chain. Select one. The canvas lays that walk out from the entry to the last hop. The right panel is the diagnosis, each hop with its file and line, and the next deletion or constraint.

A solid edge was written in a file (`EXTRACTED`). A dashed edge was resolved across files, images, or deploy steps (`INFERRED`). Scroll to zoom and drag to pan. The path's confidence is its weakest hop.

Select a node to list every elimination path through it, the edges that make the walk reachable, and what to remove. Open a finding on that node for the same record as the report: how an attacker can use it, the effect, the next step, and the exception record.

`graph-report.md` lists the god nodes (the components the most edges pass through), the communities, and each chain. `graph.json` is the same snapshot, including `graph.schema_version`.

## 8. How do I read the threat model?

The threat model is the same snapshot as the attack paths, read through the framework you already use. An exception that removed an issue from the paths also removes it from these groups. Open `threat-model.html`. The page starts as lenses, not as a dump of every finding.

Choose **Severity**, **Reachability**, **Exploitability**, **STRIDE**, **DREAD**, or **PASTA**. Then choose a group. If Critical says `Critical (4)`, that click lists those four findings and nothing else. Select a row to open it. The open record starts with how an attacker can use the finding, on this component or by moving into another component. Then:

- **Effect** — what this line allows
- **Next step** — the exact text to delete or the line to put in its place
- The walk, with file and line
- DREAD factors used by the score, the STRIDE labels, the PASTA stage, and an exception id
- **For the exception record** on every hop, including Copy and the inline false-positive mark

**Scope** lists trust boundaries and assets. **Review notes** lists the reviewer panel. **Exceptions** lists cases the remediation team has marked as false positives. Those cases are not in the severity or framework groups.

DREAD here uses the factors already on the walk. Damage follows asset value. Affected users follows exposure. Exploitability is the existing factor. Discoverability follows a public entry. Reproducibility means the walk is present in the files, so a reviewer can find it again. It is not a statement that a request was sent.

## 9. Which files did this scan open?

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

The unused-code pass reads Python, JavaScript, TypeScript, Java, Go, C#, and PHP. It recommends deletion only for a private or unexported symbol that no live code can reach. A public or exported symbol stays. Lockfiles are skipped, as are `vendor`, `third_party`, `site-packages`, `.next`, `coverage`, and `bower_components`, in addition to the directories listed below.

Directories named `.git`, `node_modules`, `venv`, `.venv`, `__pycache__`, `dist`, `build`, `out`, `data`, `.pathfinder`, and `.pytest_cache` are skipped. Files larger than 1 MB are skipped.

Python calls are resolved across files from imports. Other languages contribute routes and sinks from source patterns. If a call name is ambiguous, it is left unlinked. A bare word such as `system`, a placeholder credential, or a cache key is not a finding.

## 10. How do I measure whether a path is gone?

A GitHub, GitLab, or Azure DevOps run is a fresh scan of that commit. Locally, the first analyze of an `--out` folder is the snapshot later runs compare against. Path erasure rate is `erased / eligible`, the Path Erasure Rate from the [OWASP Subtractive Hardening Top 10](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10) baseline, and it is 0 on that first run.

After you delete a path in code, run the same command again with the same `--out` folder. The report compares chain ids with `history.json`:

- **Erased** counts chains that were in the previous run and are absent now.
- The trend line shows the previous critical count, the current count, and the reduction.

A chain counts as gone only when its narrative changes or disappears. Renaming a function without removing the edge will usually leave the chain in place.

## 11. How do I accept one false positive?

A finding stays while the structural evidence stays. When the remediation team has reviewed a hit and it is a false positive, record it in the repository that runs the action. The TemTech repository does not keep that list.

Open the calling repository and commit `pathfinder-exceptions.yml`. The root, next to `README.md`, is the usual place. A copy in any other folder is still read. `.github/workflows/attack-paths.yml` only runs the scan.

```text
calling-repository/
  README.md
  pathfinder-exceptions.yml
```

Each entry is one issue. It needs the file, the rule, the line, and a reason of at least 8 characters.

```yaml
exceptions:
  - file: admin.rb
    rule: APP05
    line: 2
    reason: Sandbox helper, not a production entry
```

That skips the APP05 issue at that line. The report path `src/admin.rb` matches `admin.rb`. `APP5` and `APP05` are the same rule. A line a few lines from the report still matches that same issue. Another finding in the file stays. A file name with no rule and no line does not clear the file.

The same mark can sit on the line in that repository, or on the comment line directly above it:

```ruby
# pathfinder: false-positive: sandbox helper, not a production entry
system(params[:cmd])
```

The next run reads the committed file from the checkout and leaves that case out of the paths, the graph, and the threat groups. A blank reason does not suppress a finding. If the exceptions file is unreadable, the scan keeps every finding and reports the file error. An older `.pathfinder/exceptions.yml` in that repository is still read.

The **Scan summary** step counts those cases as **Exceptions skipped**. In `threat-model.html`, open **Exceptions** to see the reason and who marked the case. The same record is already on every finding: open the card, copy the snippet, and fill in the reason. Unused-code removals use rule APP07.

## 12. How do I ask whether one objective is reachable?

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

## 13. How do I run a webhook on my own server?

The GitHub Action is the hook to use for a repository. A self-hosted webhook stays closed until you set a secret, so an open port cannot clone arbitrary repositories.

```bash
export GITHUB_WEBHOOK_SECRET="a long random string"
python -m pathfinder serve
```

Point a GitHub webhook at `POST /api/webhooks/github` and set the same secret. The service checks `X-Hub-Signature-256`. To also comment on the pull request from this process, set `GITHUB_TOKEN` and `PATHFINDER_POST_COMMENTS=1`. The Action does not use those variables. It comments with the workflow token.

GitLab uses `GITLAB_WEBHOOK_SECRET` and the header `X-Gitlab-Token`, posted to `/api/webhooks/gitlab`.

## 14. When would I load this into Neo4j?

`graph.cypher` in the local output creates one node per component and the edges the analyzer could prove (`CALLS`, `ROUTES_TO`, `READS`, `FLOWS_TO`, `USES_SECRET`, `DEPLOYS`, `INVOKES`, `TRUSTS`). Review the file, then load it into a database you control. The HTML reports do not require Neo4j.

## 15. What should I believe after I read the report?

Believe the file and the line, then the edge the report tells you to delete. A chain means the files contain a connected walk from an entry to a valuable target.

Confirm the file and line before you treat a hop as a defect. Python uses the AST. The languages with a dedicated parser contribute routes and sinks from source patterns. Every other program is read by the structural pass. A local model learns names this repository already confirmed and carries them to the next scan.

A score ranks removal order inside this snapshot. It is not a CVSS score, and it is not proof that a specific request would succeed. The control behind each finding is the [OWASP Subtractive Hardening Top 10](https://github.com/OWASP/OWASP-Subtractive-Hardening-Top-10) baseline: delete the edge, or constrain it when it cannot be deleted. Other framework tags, including OWASP Top 10 and STRIDE, are a way to read the same walk. They are not a certification, and this repository is not an OWASP Foundation project.

## 16. How do I add this scan to every repository?

Open `report.html` and go to **Add this scan to a repository**. The first three blocks are GitHub, GitLab, and Azure DevOps. Check out the target branch in the repository you want to scan, save the matching workflow, and push the target branch. GitHub uses `.github/workflows/attack-paths.yml`. GitLab uses `attack-paths.gitlab-ci.yml` plus an `include` in `.gitlab-ci.yml`. Azure DevOps uses `azure-pipelines/attack-paths.yml`. The application stays in that repository.

The workflow prints each file and component while the job is running, then writes the findings.

From a clone of this repository you can write the same file for another checkout:

```bash
python -m pathfinder install path/to/repository-to-scan
python -m pathfinder install path/to/repository-to-scan --platform gitlab
python -m pathfinder install path/to/repository-to-scan --platform azure
```

The GitHub file is `.github/workflows/attack-paths.yml`. The GitLab file is `attack-paths.gitlab-ci.yml`. The Azure DevOps file is `azure-pipelines/attack-paths.yml`. Push the file, then open the pipeline log. The log lists each file and each component as it is analyzed.

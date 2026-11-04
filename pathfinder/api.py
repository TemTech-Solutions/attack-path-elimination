"""Local review service.

The process parses repositories. It does not import them, install their
dependencies, or run their tests. Webhooks are inert unless a shared secret
is configured, so an exposed port cannot be used as an open clone proxy.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from pathfinder.analyze import analyze
from pathfinder.report import pr_comment, render_html, render_threat_html

ALLOWED_HOSTS = {"github.com", "gitlab.com", "dev.azure.com"}
app = FastAPI(title="Attack path elimination", version="0.1.0")
LAST: dict | None = None


@app.get("/", response_class=HTMLResponse)
def home():
    report = Path(os.environ.get("PATHFINDER_REPORT", "out")) / "report.html"
    if report.exists():
        return HTMLResponse(report.read_text(encoding="utf-8"))
    return HTMLResponse(
        "<html><body style='font-family:sans-serif;background:#0c1222;color:#e7eefc;padding:32px'>"
        "<h1>Attack path elimination</h1>"
        "<p>Add <code>install/github/attack-paths.yml</code> from the public platform repository "
        "to the application repository, or POST /api/analyze with a local path under the working directory.</p>"
        "</body></html>"
    )


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/scorecard")
def scorecard():
    if LAST is None:
        raise HTTPException(404, "No analysis yet")
    return LAST["scorecard"]


@app.get("/api/paths")
def paths():
    if LAST is None:
        raise HTTPException(404, "No analysis yet")
    return LAST["paths"]


@app.get("/graph.html", response_class=HTMLResponse)
def graph_page():
    page = Path(os.environ.get("PATHFINDER_REPORT", "out")) / "graph.html"
    if page.exists():
        return HTMLResponse(page.read_text(encoding="utf-8"))
    raise HTTPException(404, "No graph yet. Run analyze first.")


@app.get("/api/graph")
def graph():
    if LAST is None:
        raise HTTPException(404, "No analysis yet")
    if LAST.get("graph"):
        return LAST["graph"]
    return {"nodes": LAST["nodes"], "edges": LAST["edges"]}


@app.post("/api/analyze")
async def analyze_request(request: Request):
    body = await request.json()
    target = body.get("target") or body.get("path")
    if not target:
        raise HTTPException(400, "target is required")
    root = _resolve_target(str(target))
    result = analyze(root)
    _remember(result)
    return {"scorecard": result["scorecard"], "paths": result["paths"], "comment": pr_comment(result)}


@app.post("/api/webhooks/github")
async def github_webhook(request: Request):
    raw = await request.body()
    _verify_github(raw, request.headers.get("x-hub-signature-256"))
    payload = json.loads(raw.decode("utf-8") or "{}")
    clone_url = ((payload.get("repository") or {}).get("clone_url"))
    if not clone_url:
        raise HTTPException(400, "repository.clone_url is required")
    result = analyze(_clone(clone_url))
    _remember(result)
    comment = pr_comment(result)
    posted = _maybe_post_github(payload, comment)
    return {"scorecard": result["scorecard"], "comment": comment, "posted": posted}


@app.post("/api/webhooks/gitlab")
async def gitlab_webhook(request: Request):
    token = request.headers.get("x-gitlab-token")
    expected = os.environ.get("GITLAB_WEBHOOK_SECRET")
    if not expected or not token or not hmac.compare_digest(token, expected):
        raise HTTPException(403, "Set GITLAB_WEBHOOK_SECRET and send it in X-Gitlab-Token")
    payload = await request.json()
    clone_url = ((payload.get("project") or {}).get("git_http_url")) or ((payload.get("repository") or {}).get("git_http_url"))
    if not clone_url:
        raise HTTPException(400, "project.git_http_url is required")
    result = analyze(_clone(clone_url))
    _remember(result)
    return {"scorecard": result["scorecard"], "comment": pr_comment(result)}


def serve(host: str, port: int, report_dir: Path) -> None:
    os.environ["PATHFINDER_REPORT"] = str(report_dir)
    import uvicorn

    uvicorn.run("pathfinder.api:app", host=host, port=port, reload=False)


def _remember(result: dict) -> None:
    global LAST
    LAST = result
    report_dir = Path(os.environ.get("PATHFINDER_REPORT", "out"))
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "report.html").write_text(render_html(result), encoding="utf-8")
    (report_dir / "threat-model.html").write_text(render_threat_html(result), encoding="utf-8")


def _resolve_target(target: str) -> Path:
    if target.startswith("https://"):
        return _clone(target)
    path = Path(target).resolve()
    allowed = [Path.cwd().resolve()]
    extra = os.environ.get("PATHFINDER_ALLOWED_ROOT")
    if extra:
        allowed.append(Path(extra).resolve())
    if not any(_is_relative_to(path, root) for root in allowed):
        raise HTTPException(403, "Path is outside the allowed analysis root")
    if not path.exists():
        raise HTTPException(404, "Path does not exist")
    return path


def _clone(url: str) -> Path:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        raise HTTPException(400, "Only https repository URLs without embedded credentials are accepted")
    host = (parsed.hostname or "").lower()
    if not host or _is_ip(host) or not _host_allowed(host):
        raise HTTPException(400, "Repository host is not in the allow list")
    destination = Path("data") / "clones" / hashlib.sha256(url.encode()).hexdigest()[:16]
    if destination.exists():
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(destination)],
            check=True,
            timeout=120,
            capture_output=True,
            text=True,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise HTTPException(502, "Clone failed") from exc
    return destination


def _host_allowed(host: str) -> bool:
    allowed = set(ALLOWED_HOSTS)
    extra = os.environ.get("PATHFINDER_GIT_HOSTS", "")
    allowed.update(item.strip().lower() for item in extra.split(",") if item.strip())
    return any(host == name or host.endswith("." + name) for name in allowed)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _verify_github(raw: bytes, signature: str | None) -> None:
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(403, "Set GITHUB_WEBHOOK_SECRET before accepting webhooks")
    if not signature or not signature.startswith("sha256="):
        raise HTTPException(403, "Missing signature")
    expected = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature.removeprefix("sha256="), expected):
        raise HTTPException(403, "Bad signature")


def _maybe_post_github(payload: dict, comment: str) -> bool:
    token = os.environ.get("GITHUB_TOKEN")
    if os.environ.get("PATHFINDER_POST_COMMENTS") != "1" or not token:
        return False
    pull = payload.get("pull_request") or {}
    number = pull.get("number")
    repo = (payload.get("repository") or {}).get("full_name")
    if not number or not repo:
        return False
    import urllib.request

    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/issues/{number}/comments",
        data=json.dumps({"body": comment}).encode(),
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "User-Agent": "pathfinder"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return 200 <= response.status < 300

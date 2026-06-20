"""
SecureAudit web dashboard — FastAPI + Jinja2.
Start with: secureaudit serve --db audits.db

REST API for write operations (POST /api/scan, POST /api/projects/{name}/webhooks)
is token-gated when the dashboard is bound to anything other than localhost —
see `secureaudit serve --token` / the SECUREAUDIT_API_TOKEN env var.
"""

from __future__ import annotations

import uuid

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from secureaudit.reports.history import (
    get_project_run_count,
    get_projects,
    get_run_findings,
    get_runs,
)

_CSS = """
<style>
:root{--bg:#0f1117;--surface:#1a1d27;--border:#2a2d3a;--accent:#4f8ef7;
--text:#e2e8f0;--muted:#64748b;--critical:#ef4444;--high:#f97316;
--medium:#f59e0b;--low:#3b82f6;--ok:#22c55e;}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:system-ui,sans-serif;padding:2rem}
h1{font-size:1.6rem;font-weight:700;color:var(--accent);margin-bottom:.25rem}
h2{font-size:1rem;font-weight:600;margin-bottom:.75rem}
.sub{color:var(--muted);font-size:.85rem;margin-bottom:1.5rem}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
table{width:100%;border-collapse:collapse;font-size:.88rem}
th{text-align:left;padding:.5rem .75rem;color:var(--muted);font-weight:500;border-bottom:1px solid var(--border)}
td{padding:.5rem .75rem;border-bottom:1px solid #1f2230}
tr:last-child td{border:none}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1.25rem;margin-bottom:1rem}
.grade{font-size:2rem;font-weight:900}
.grade-A{color:var(--ok)} .grade-B{color:#86efac} .grade-C{color:var(--medium)}
.grade-D{color:var(--high)} .grade-F{color:var(--critical)}
.badge{display:inline-block;padding:.1rem .4rem;border-radius:3px;font-size:.72rem;font-weight:700}
.CRITICAL{background:#3f1010;color:var(--critical)}
.HIGH{background:#3f1f08;color:var(--high)}
.MEDIUM{background:#3f2a00;color:var(--medium)}
.LOW{background:#0c1f3f;color:var(--low)}
.INFO{background:#1a1d27;color:var(--muted)}
footer{color:var(--muted);font-size:.75rem;margin-top:2rem;text-align:center}
</style>
"""


class ScanRequest(BaseModel):
    target: str
    plugins: list[str] | None = None
    config: str | None = None
    project: str | None = None


class WebhookRequest(BaseModel):
    url: str


def create_app(db_path: str, api_token: str | None = None, require_token: bool = False) -> FastAPI:
    app = FastAPI(title="SecureAudit Dashboard")
    app.state.pending_scans = {}

    async def verify_token(authorization: str | None = Header(default=None)) -> None:
        """Dependency for write endpoints. No-op when the dashboard has no
        token configured and isn't required to have one (localhost default)."""
        if not require_token and not api_token:
            return
        if not api_token:
            raise HTTPException(status_code=503, detail="Server misconfigured: no API token set.")
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing or malformed Authorization header.")
        provided = authorization[len("Bearer "):]
        if provided != api_token:
            raise HTTPException(status_code=401, detail="Invalid API token.")

    @app.get("/", response_class=HTMLResponse)
    async def index():
        runs = get_runs(db_path, limit=50)
        rows = ""
        for r in runs:
            grade = r["grade"]
            score_color = "ok" if r["score"] >= 75 else "medium" if r["score"] >= 60 else "critical"
            rows += (
                f'<tr><td><a href="/run/{r["id"]}">#{r["id"]}</a></td>'
                f'<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">{r["target"]}</td>'
                f'<td>{r["timestamp"][:16]}</td>'
                f'<td style="color:var(--{score_color})">{r["score"]}</td>'
                f'<td class="grade grade-{grade}">{grade}</td>'
                f'<td style="color:var(--critical)">{r["critical_high"]}</td>'
                f'<td>{r["total_findings"]}</td></tr>\n'
            )

        if not rows:
            rows = '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:2rem">No audit runs yet. Run: <code>secureaudit scan . --db audits.db</code></td></tr>'

        return HTMLResponse(f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>SecureAudit Dashboard</title>{_CSS}</head><body>
<h1>🔐 SecureAudit</h1>
<p class="sub">Audit history — <a href="/projects">Projects</a> — <a href="/api/runs">JSON API</a></p>
<div class="card">
<h2>Recent Runs</h2>
<table><tr><th>#</th><th>Target</th><th>Timestamp</th><th>Score</th><th>Grade</th><th>High+Critical</th><th>Total entries</th></tr>
{rows}</table></div>
<footer>SecureAudit Dashboard</footer>
</body></html>""")

    @app.get("/run/{run_id}", response_class=HTMLResponse)
    async def run_detail(run_id: int):
        runs = get_runs(db_path)
        run = next((r for r in runs if r["id"] == run_id), None)
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")

        findings = get_run_findings(db_path, run_id)
        rows = ""
        for f in sorted(findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x["severity"])):
            rows += (
                f'<tr><td><span class="badge {f["severity"]}">{f["severity"]}</span></td>'
                f'<td>{f["plugin"]}</td><td>{f["title"]}</td>'
                f'<td style="font-family:monospace;font-size:.8rem">'
                f'{f["file"] or ""}{(":" + str(f["line"])) if f["line"] else ""}</td></tr>\n'
            )
        if not rows:
            rows = '<tr><td colspan="4" style="color:var(--ok)">No findings</td></tr>'

        grade = run["grade"]
        return HTMLResponse(f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Run #{run_id}</title>{_CSS}</head><body>
<p><a href="/">← Back</a></p>
<h1>Run #{run_id}</h1>
<p class="sub">{run["target"]} — {run["timestamp"][:16]}</p>
<div class="card" style="display:flex;gap:2rem;align-items:center">
  <div><div class="grade grade-{grade}">{run["score"]}</div><div style="color:var(--muted)">Score</div></div>
  <div><div class="grade grade-{grade}">{grade}</div><div style="color:var(--muted)">Grade</div></div>
  <div><div style="font-size:1.5rem;color:var(--critical)">{run["critical_high"]}</div><div style="color:var(--muted)">High+Critical</div></div>
  <div><div style="font-size:1.5rem">{run["total_findings"]}</div><div style="color:var(--muted)">Total findings</div></div>
  <div><div style="font-size:1.5rem;color:var(--muted)">{run["suppressed_count"]}</div><div style="color:var(--muted)">Suppressed</div></div>
  <div><div style="font-size:1rem;color:var(--muted)">{run["duration_ms"]:.0f}ms</div><div style="color:var(--muted)">Duration</div></div>
</div>
<div class="card">
<h2>Findings ({len(findings)})</h2>
<table><tr><th>Severity</th><th>Plugin</th><th>Title</th><th>Location</th></tr>
{rows}</table></div>
<footer>SecureAudit Dashboard</footer>
</body></html>""")

    @app.get("/projects", response_class=HTMLResponse)
    async def projects_index():
        rows_data = get_projects(db_path)
        rows = ""
        for r in rows_data:
            grade = r["grade"]
            score_color = "ok" if r["score"] >= 75 else "medium" if r["score"] >= 60 else "critical"
            run_count = get_project_run_count(db_path, r["project"])
            rows += (
                f'<tr><td><a href="/projects/{r["project"]}">{r["project"]}</a></td>'
                f'<td style="color:var(--{score_color})">{r["score"]}</td>'
                f'<td class="grade grade-{grade}">{grade}</td>'
                f'<td>{run_count}</td>'
                f'<td>{r["timestamp"][:16]}</td></tr>\n'
            )

        if not rows:
            rows = (
                '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:2rem">'
                "No projects yet. Add <code>project: your-name</code> to secureaudit.yml "
                "and scan with <code>--db</code>.</td></tr>"
            )

        return HTMLResponse(f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Projects — SecureAudit Dashboard</title>{_CSS}</head><body>
<p><a href="/">← All runs</a></p>
<h1>📁 Projects</h1>
<p class="sub">Portfolio overview — latest score per project</p>
<div class="card">
<table><tr><th>Project</th><th>Latest Score</th><th>Grade</th><th>Runs</th><th>Last scan</th></tr>
{rows}</table></div>
<footer>SecureAudit Dashboard</footer>
</body></html>""")

    @app.get("/projects/{project_name}", response_class=HTMLResponse)
    async def project_detail(project_name: str):
        runs = get_runs(db_path, limit=100, project=project_name)
        if not runs:
            raise HTTPException(status_code=404, detail="Project not found")

        rows = ""
        for r in runs:
            grade = r["grade"]
            score_color = "ok" if r["score"] >= 75 else "medium" if r["score"] >= 60 else "critical"
            rows += (
                f'<tr><td><a href="/run/{r["id"]}">#{r["id"]}</a></td>'
                f'<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">{r["target"]}</td>'
                f'<td>{r["timestamp"][:16]}</td>'
                f'<td style="color:var(--{score_color})">{r["score"]}</td>'
                f'<td class="grade grade-{grade}">{grade}</td>'
                f'<td style="color:var(--critical)">{r["critical_high"]}</td></tr>\n'
            )

        # Trend: oldest → newest for the chart, runs themselves stay newest-first in the table
        trend = list(reversed(runs))
        labels = [r["timestamp"][:10] for r in trend]
        scores = [r["score"] for r in trend]

        latest = runs[0]
        return HTMLResponse(f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>{project_name} — SecureAudit Dashboard</title>{_CSS}
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head><body>
<p><a href="/projects">← All projects</a></p>
<h1>📁 {project_name}</h1>
<p class="sub">{len(runs)} run(s) — latest grade <span class="grade grade-{latest["grade"]}">{latest["grade"]}</span></p>
<div class="card">
<h2>Score Trend</h2>
<div style="height:220px;position:relative"><canvas id="trendChart"></canvas></div>
</div>
<div class="card">
<h2>Runs</h2>
<table><tr><th>#</th><th>Target</th><th>Timestamp</th><th>Score</th><th>Grade</th><th>High+Critical</th></tr>
{rows}</table></div>
<footer>SecureAudit Dashboard</footer>
<script>
new Chart(document.getElementById('trendChart'), {{
  type: 'line',
  data: {{
    labels: {labels!r},
    datasets: [{{
      label: 'Score',
      data: {scores!r},
      borderColor: '#4f8ef7',
      backgroundColor: '#4f8ef722',
      fill: true,
      tension: 0.3,
      pointRadius: 3,
    }}]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    scales: {{ y: {{ min: 0, max: 100, ticks: {{ color: '#64748b' }} }},
               x: {{ ticks: {{ color: '#64748b' }} }} }},
    plugins: {{ legend: {{ display: false }} }}
  }}
}});
</script>
</body></html>""")

    @app.get("/api/runs")
    async def api_runs(limit: int = 20, project: str | None = None):
        return JSONResponse(get_runs(db_path, limit=limit, project=project))

    @app.get("/api/projects")
    async def api_projects():
        return JSONResponse(get_projects(db_path))

    @app.get("/api/runs/{run_id}/findings")
    async def api_findings(run_id: int, severity: str | None = None):
        """Filterable findings endpoint — e.g. ?severity=CRITICAL"""
        return JSONResponse(get_run_findings(db_path, run_id, severity=severity))

    # ── Async scan trigger ────────────────────────────────────────────────────

    def _run_scan_background(scan_id: str, req: ScanRequest) -> None:
        from pathlib import Path as _Path

        from secureaudit.core.config import load_config
        from secureaudit.core.engine import AuditEngine
        from secureaudit.reports.history import save

        try:
            config_path = req.config or str(_Path(req.target) / "secureaudit.yml")
            cfg = load_config(config_path)
            engine = AuditEngine(cfg)
            result = engine.run(req.target, req.plugins)

            project = req.project or cfg.project
            run_id = save(result, db_path, project=project)

            app.state.pending_scans[scan_id] = {
                "status": "completed", "run_id": run_id, "error": None,
            }

            if project:
                from secureaudit.core.webhooks import check_and_fire_project_webhooks
                check_and_fire_project_webhooks(db_path, project, run_id)
        except Exception as exc:
            app.state.pending_scans[scan_id] = {
                "status": "failed", "run_id": None, "error": str(exc),
            }

    @app.post("/api/scan", dependencies=[Depends(verify_token)])
    async def api_trigger_scan(req: ScanRequest, background_tasks: BackgroundTasks):
        """Trigger a scan against `target`. Returns immediately with a scan_id
        to poll via GET /api/scan/{scan_id} — the scan itself runs in the
        background and is only persisted to history once it completes."""
        scan_id = str(uuid.uuid4())
        app.state.pending_scans[scan_id] = {"status": "running", "run_id": None, "error": None}
        background_tasks.add_task(_run_scan_background, scan_id, req)
        return {"scan_id": scan_id, "status": "running"}

    @app.get("/api/scan/{scan_id}")
    async def api_scan_status(scan_id: str):
        pending = app.state.pending_scans.get(scan_id)
        if pending is None:
            raise HTTPException(status_code=404, detail="Unknown scan_id")
        return {"scan_id": scan_id, **pending}

    # ── Project webhooks ──────────────────────────────────────────────────────

    @app.post("/api/projects/{project_name}/webhooks", dependencies=[Depends(verify_token)])
    async def api_register_webhook(project_name: str, body: WebhookRequest):
        from secureaudit.core.webhooks import register_webhook
        webhook_id = register_webhook(db_path, project_name, body.url)
        return {"id": webhook_id, "project": project_name, "url": body.url}

    @app.get("/api/projects/{project_name}/webhooks", dependencies=[Depends(verify_token)])
    async def api_list_webhooks(project_name: str):
        from secureaudit.core.webhooks import get_webhooks
        return JSONResponse(get_webhooks(db_path, project_name))

    @app.delete("/api/projects/{project_name}/webhooks/{webhook_id}", dependencies=[Depends(verify_token)])
    async def api_delete_webhook(project_name: str, webhook_id: int):
        from secureaudit.core.webhooks import delete_webhook
        deleted = delete_webhook(db_path, webhook_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Webhook not found")
        return {"deleted": True, "id": webhook_id}

    return app

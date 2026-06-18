"""
SecureAudit web dashboard — FastAPI + Jinja2.
Start with: secureaudit serve --db audits.db
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from secureaudit.reports.history import get_run_findings, get_runs

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


def create_app(db_path: str) -> FastAPI:
    app = FastAPI(title="SecureAudit Dashboard", docs_url=None, redoc_url=None)

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
<p class="sub">Audit history — <a href="/api/runs">JSON API</a></p>
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

    @app.get("/api/runs")
    async def api_runs(limit: int = 20):
        return JSONResponse(get_runs(db_path, limit=limit))

    @app.get("/api/runs/{run_id}/findings")
    async def api_findings(run_id: int):
        return JSONResponse(get_run_findings(db_path, run_id))

    return app

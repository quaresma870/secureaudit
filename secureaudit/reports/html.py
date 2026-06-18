"""
HTML report — self-contained report with Chart.js.
"""

from __future__ import annotations

import json
from pathlib import Path

from secureaudit.core.models import AuditResult, Severity

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureAudit Report — {target}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {{
    --bg:#0f1117;--surface:#1a1d27;--border:#2a2d3a;
    --accent:#4f8ef7;--text:#e2e8f0;--muted:#64748b;
    --critical:#ef4444;--high:#f97316;--medium:#f59e0b;--low:#3b82f6;--info:#6b7280;
  }}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:system-ui,sans-serif;padding:2rem}}
  h1{{font-size:1.8rem;font-weight:700;color:var(--accent)}}
  h2{{font-size:1.1rem;font-weight:600;margin-bottom:1rem}}
  .sub{{color:var(--muted);font-size:.9rem;margin:.25rem 0 2rem}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-bottom:1.5rem}}
  .card{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.25rem}}
  .score{{font-size:3rem;font-weight:900;line-height:1}}
  .grade{{font-size:1.5rem;font-weight:700;margin-top:.25rem}}
  .stat{{font-size:2rem;font-weight:700}}
  .label{{color:var(--muted);font-size:.8rem;margin-top:.3rem}}
  .critical{{color:var(--critical)}} .high{{color:var(--high)}} .medium{{color:var(--medium)}} .low{{color:var(--low)}} .info{{color:var(--info)}}
  table{{width:100%;border-collapse:collapse;font-size:.88rem}}
  th{{text-align:left;padding:.6rem .75rem;color:var(--muted);font-weight:500;border-bottom:1px solid var(--border)}}
  td{{padding:.55rem .75rem;border-bottom:1px solid #1f2230;vertical-align:top}}
  tr:last-child td{{border:none}}
  .badge{{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.72rem;font-weight:700}}
  .badge-CRITICAL{{background:#3f1010;color:var(--critical)}}
  .badge-HIGH{{background:#3f1f08;color:var(--high)}}
  .badge-MEDIUM{{background:#3f2a00;color:var(--medium)}}
  .badge-LOW{{background:#0c1f3f;color:var(--low)}}
  .badge-INFO{{background:#1a1d27;color:var(--info)}}
  .plugin-ok{{color:#22c55e}}
  .plugin-fail{{color:var(--critical)}}
  .chart-wrap{{height:220px;position:relative}}
  details{{margin:.5rem 0}}
  summary{{cursor:pointer;color:var(--muted);font-size:.8rem}}
  code{{font-family:monospace;font-size:.8rem;background:#1f2230;padding:.1rem .3rem;border-radius:3px;word-break:break-all}}
  footer{{color:var(--muted);font-size:.75rem;margin-top:3rem;text-align:center}}
</style>
</head>
<body>
<h1>🔐 SecureAudit Report</h1>
<p class="sub">Target: <code>{target}</code> &nbsp;|&nbsp; {timestamp} &nbsp;|&nbsp; Duration: {duration}ms</p>

<div class="grid">
  <div class="card">
    <div class="score {score_class}">{score}</div>
    <div class="grade {score_class}">Grade {grade}</div>
    <div class="label">Security Score</div>
  </div>
  <div class="card">
    <div class="stat critical">{critical}</div>
    <div class="label">Critical</div>
  </div>
  <div class="card">
    <div class="stat high">{high}</div>
    <div class="label">High</div>
  </div>
  <div class="card">
    <div class="stat medium">{medium}</div>
    <div class="label">Medium</div>
  </div>
  <div class="card">
    <div class="stat low">{low}</div>
    <div class="label">Low / Info</div>
  </div>
</div>

<div class="grid" style="margin-bottom:2rem">
  <div class="card">
    <h2>Findings by Severity</h2>
    <div class="chart-wrap"><canvas id="sevChart"></canvas></div>
  </div>
  <div class="card">
    <h2>Plugin Scores</h2>
    <div class="chart-wrap"><canvas id="pluginChart"></canvas></div>
  </div>
</div>

<div class="card" style="margin-bottom:1.5rem">
  <h2>Plugin Summary</h2>
  <table>
    <tr><th>Plugin</th><th>Score</th><th>Findings</th><th>Status</th></tr>
    {plugin_rows}
  </table>
</div>

<div class="card">
  <h2>All Findings</h2>
  <table>
    <tr><th>Severity</th><th>Plugin</th><th>Title</th><th>Details</th></tr>
    {finding_rows}
  </table>
</div>

<footer>SecureAudit &nbsp;|&nbsp; {timestamp}</footer>

<script>
const DATA = {json_data};

new Chart(document.getElementById('sevChart'), {{
  type: 'doughnut',
  data: {{
    labels: ['Critical','High','Medium','Low','Info'],
    datasets: [{{
      data: [DATA.severity_counts.CRITICAL,DATA.severity_counts.HIGH,DATA.severity_counts.MEDIUM,DATA.severity_counts.LOW,DATA.severity_counts.INFO],
      backgroundColor:['#ef444488','#f9731688','#f59e0b88','#3b82f688','#6b728088'],
      borderColor:['#ef4444','#f97316','#f59e0b','#3b82f6','#6b7280'],borderWidth:1
    }}]
  }},
  options:{{responsive:true,maintainAspectRatio:false,plugins:{{legend:{{labels:{{color:'#e2e8f0'}}}}}}}}
}});

new Chart(document.getElementById('pluginChart'), {{
  type: 'bar',
  data: {{
    labels: DATA.plugins.map(p=>p.plugin),
    datasets: [{{
      label: 'Score',
      data: DATA.plugins.map(p=>p.score),
      backgroundColor: DATA.plugins.map(p => p.score>=80?'#22c55e88':p.score>=60?'#f59e0b88':'#ef444488'),
      borderColor: DATA.plugins.map(p => p.score>=80?'#22c55e':p.score>=60?'#f59e0b':'#ef4444'),
      borderWidth:1
    }}]
  }},
  options:{{responsive:true,maintainAspectRatio:false,
    plugins:{{legend:{{display:false}}}},
    scales:{{y:{{min:0,max:100,ticks:{{color:'#64748b'}}}},x:{{ticks:{{color:'#64748b'}}}}}}
  }}
}});
</script>
</body>
</html>"""


def write_html(result: AuditResult, path: str | Path) -> None:
    counts = result.counts_by_severity()
    score = result.score
    score_class = "critical" if score < 40 else "high" if score < 60 else "medium" if score < 75 else "info"

    plugin_rows = ""
    for pr in result.plugin_results:
        status = '<span class="plugin-fail">✘ FAIL</span>' if not pr.passed else '<span class="plugin-ok">✔ PASS</span>'
        if pr.error:
            status = '<span class="plugin-fail">⚠ ERROR</span>'
        plugin_rows += f"<tr><td>{pr.plugin}</td><td>{pr.score}</td><td>{len(pr.findings)}</td><td>{status}</td></tr>\n"

    finding_rows = ""
    for f in sorted(result.all_findings, key=lambda x: list(Severity).index(x.severity)):
        details = f.description[:120]
        if f.file:
            details += f"<br><code>{f.file}{':' + str(f.line) if f.line else ''}</code>"
        if f.remediation:
            details += f"<br><details><summary>Remediation</summary><code>{f.remediation}</code></details>"
        finding_rows += (
            f'<tr><td><span class="badge badge-{f.severity.value}">{f.severity.value}</span></td>'
            f"<td>{f.plugin}</td><td>{f.title}</td><td>{details}</td></tr>\n"
        )

    html = _TEMPLATE.format(
        target=result.target,
        timestamp=result.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
        duration=f"{result.duration_ms:.0f}",
        score=score,
        grade=result.grade,
        score_class=score_class,
        critical=counts.get("CRITICAL", 0),
        high=counts.get("HIGH", 0),
        medium=counts.get("MEDIUM", 0),
        low=counts.get("LOW", 0) + counts.get("INFO", 0),
        plugin_rows=plugin_rows,
        finding_rows=finding_rows or "<tr><td colspan='4' style='text-align:center;color:var(--muted)'>No findings</td></tr>",
        json_data=json.dumps(result.to_dict(), default=str),
    )

    Path(path).write_text(html, encoding="utf-8")

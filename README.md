# 🔐 SecureAudit

[![CI](https://github.com/quaresma870/secureaudit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/quaresma870/secureaudit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)
![Node.js](https://img.shields.io/badge/GitHub%20Actions-Node.js%2024-brightgreen?logo=nodedotjs&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

Multi-plugin security audit tool. Scans repositories and infrastructure for secrets, CVEs, misconfigurations, HTTP header issues, open ports and policy violations — producing a security score, HTML report and CI integration.

---

## Features

- ✅ **6 plugins** — secrets, CVE, filesystem, HTTP headers, network, policy
- ✅ **Security score** 0–100 with letter grade (A–F)
- ✅ **Severity levels** — Critical / High / Medium / Low / Info
- ✅ **HTML report** — self-contained with Chart.js charts
- ✅ **JSON output** — machine-readable for integrations
- ✅ **GitHub Action** — block PRs if score drops below threshold
- ✅ **Config file** — `secureaudit.yml` for full customisation
- ✅ **25 tests** — models, plugins, engine

---

## Plugins

| Plugin | What it checks |
|--------|---------------|
| `secrets` | API keys, tokens, passwords, private keys — regex + entropy filter |
| `cve` | Dependency CVEs via [OSV.dev](https://osv.dev) — PyPI, npm, Go |
| `filesystem` | Sensitive committed files, world-writable files, SUID bits |
| `http` | Security headers (HSTS, CSP, X-Frame-Options…), SSL expiry, redirects |
| `network` | Open ports — database, telnet, VNC, Redis exposed to internet |
| `policy` | `.gitignore` completeness, Dockerfile USER, unpinned deps, CI hardening |
| `cors` | CORS misconfiguration — origin reflection, wildcard + credentials, null origin |
| `git_history` | Git history scan — secrets committed and later removed |
| `sast` | Static code analysis via Semgrep — SQLi, command injection, SSRF, etc. (opt-in) |
| `malware` | Known malware signatures via ClamAV — supply-chain attacks (opt-in) |
| `trivy` | Container/filesystem CVEs + IaC misconfig via Trivy (opt-in) |

---

## Installation

```bash
git clone https://github.com/quaresma870/secureaudit.git
cd secureaudit
pip install -r requirements.txt
```

---

## Usage

### CLI

```bash
# Scan current directory (all plugins)
PYTHONPATH=. python -m secureaudit.cli scan .

# Specific plugins only
PYTHONPATH=. python -m secureaudit.cli scan . --plugins secrets,cve,policy

# Generate HTML + JSON report
PYTHONPATH=. python -m secureaudit.cli scan . --output report.html --json report.json

# Fail if score below 80
PYTHONPATH=. python -m secureaudit.cli scan . --fail-below 80

# Scheduled audit (weekly, alert on regression)
PYTHONPATH=. python -m secureaudit.cli schedule . --cron "0 6 * * 1" --db audits.db --alert-webhook URL

# Accept current findings as baseline (run once after initial triage)
PYTHONPATH=. python -m secureaudit.cli baseline .

# Scan — baseline and inline suppressions applied automatically
PYTHONPATH=. python -m secureaudit.cli scan .

# List available plugins
PYTHONPATH=. python -m secureaudit.cli list-plugins
```

### GitHub Action

Add to your workflow to audit every PR:

```yaml
- name: Security Audit
  uses: quaresma870/secureaudit@main
  with:
    plugins: secrets,cve,filesystem,policy
    fail-below: "70"
    output-html: secureaudit-report.html
    output-json: secureaudit-report.json
```

---

## Configuration

Copy `secureaudit.yml.example` to `secureaudit.yml` at your project root:

```yaml
plugins:
  - secrets
  - cve
  - filesystem
  - http
  - network
  - policy

fail_below: 70

http:
  urls:
    - https://example.com

network:
  hosts:
    - example.com
```

---

## Scoring

Each finding reduces the score:

| Severity | Penalty |
|----------|---------|
| Critical | −25 pts |
| High | −15 pts |
| Medium | −7 pts |
| Low | −3 pts |
| Info | −0 pts |

| Score | Grade |
|-------|-------|
| 90–100 | A |
| 75–89 | B |
| 60–74 | C |
| 40–59 | D |
| 0–39 | F |

---

## Project structure

```
secureaudit/
├── secureaudit/
│   ├── cli.py                  # Click CLI — scan + list-plugins
│   ├── core/
│   │   ├── models.py           # Finding, AuditResult, Severity, PluginResult
│   │   ├── engine.py           # Orchestrator — loads and runs all plugins
│   │   └── config.py           # Config loader (secureaudit.yml + defaults)
│   ├── plugins/
│   │   ├── __init__.py         # BasePlugin + plugin registry
│   │   ├── secrets.py          # Regex + entropy secret detection
│   │   ├── cve.py              # OSV.dev dependency audit
│   │   ├── filesystem.py       # Permissions + sensitive files
│   │   ├── http_headers.py     # HTTP security headers + SSL
│   │   ├── network.py          # Port scanner
│   │   └── policy.py           # Dockerfile, .gitignore, CI checks
│   └── reports/
│       ├── html.py             # Self-contained HTML with Chart.js
│       └── json_report.py      # JSON serialiser
├── tests/
│   └── test_secureaudit.py     # 25 tests
├── action.yml                  # GitHub Action definition
├── secureaudit.yml.example     # Config template
├── .github/workflows/ci.yml    # Lint + test pipeline
├── requirements.txt
└── pyproject.toml
```

---

## Running tests

```bash
PYTHONPATH=. pytest tests/ -v
```

---

## Changelog

### v1.0.5
- feat: baseline command (`secureaudit baseline .`) — accept existing findings as known risk — closes #16
  (`.secureaudit-baseline.json`, fingerprint independent of line-number drift, merge or `--force` replace)
- feat: inline suppression via `# secureaudit-ignore` comments — closes #16
  (optional rule slug, `reason="..."`, and `until=YYYY-MM-DD` for forced re-review)
- feat: suppressed findings shown separately in terminal/HTML reports (not hidden, excluded from score)
- fix: `scan` command was missing `--sarif`/`--db` option decorators despite using them — caused
  a `TypeError` at invocation; added CLI integration tests (`CliRunner`) to catch this class of bug going forward
- fix: `reports/history.py` referenced non-existent `AuditResult.total`/`.sources`/`.error_rate` —
  rewrote SQLite schema to match actual model fields, added `suppressed_count` tracking
- fix: dashboard updated to match corrected history schema column names

### v1.0.4
- feat: SAST plugin via Semgrep (`sast`) — closes #13
  (3000+ OWASP Top 10 rules, runs entirely locally, graceful degradation if not installed)
- feat: malware scanning via ClamAV (`malware`) — closes #14
  (scans node_modules/.venv/uploads for known malware signatures, stale definitions warning)
- feat: container + IaC scanning via Trivy (`trivy`) — closes #15
  (broader ecosystem than OSV.dev: Cargo/Composer/NuGet; Dockerfile/K8s/Terraform misconfig)
- chore: `cors` and `git_history` added to default plugin list

### v1.0.3
- feat: CORS misconfiguration plugin (`cors`) — closes #7
  (origin reflection, wildcard + credentials, null origin — maps to OWASP)
- feat: git history secret scanner plugin (`git_history`) — closes #8
  (scans commit diffs for secrets removed from working tree; reports commit SHA + author)
- feat: `secureaudit schedule` — scheduled audit mode — closes #9
  (cron expression, regression detection — only alerts on score drop)

### v1.0.2
- feat: SARIF 2.1.0 output (`--sarif results.sarif`) for GitHub Security tab — closes #2
- feat: SQLite audit history (`--db audits.db`) + `history` subcommand — closes #4
- feat: web dashboard (`secureaudit serve --db audits.db`) at `http://localhost:8080` — closes #5
  (`GET /` history, `GET /run/{id}` details, `GET /api/runs` JSON API)

### v1.0.1
- fix: `datetime.utcnow()` → `datetime.now(timezone.utc)` — closes #3
- fix: CVE plugin reports network failures as `INFO` finding — closes #6
- feat: plugins run in parallel via `ThreadPoolExecutor` (~4× faster) — closes #1

---

## License

MIT

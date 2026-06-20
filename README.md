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
pip install secureaudit
```

```bash
# macOS / Linuxbrew
brew tap quaresma870/secureaudit
brew install secureaudit
```

Optional extras:

```bash
pip install secureaudit[sast]        # adds semgrep for the sast plugin
pip install secureaudit[dashboard]   # adds fastapi+uvicorn for `secureaudit serve`
pip install secureaudit[all]         # everything above
```

**For contributors** — clone and run from source:

```bash
git clone https://github.com/quaresma870/secureaudit.git
cd secureaudit
pip install -r requirements.txt
# then use: PYTHONPATH=. python -m secureaudit.cli <command>
```

---

## Usage

### CLI

If installed via `pip`/`brew`, use `secureaudit` directly. Running from a
source clone instead, prefix every command with `PYTHONPATH=. python -m secureaudit.cli`.

```bash
# First-time setup — detects your stack, writes secureaudit.yml, creates baseline
secureaudit init .

# Scan current directory (all plugins) — baseline/inline suppressions applied automatically
secureaudit scan .

# Specific plugins only
secureaudit scan . --plugins secrets,cve,policy

# Generate HTML + JSON report
secureaudit scan . --output report.html --json report.json

# Fail if score below 80
secureaudit scan . --fail-below 80

# Accept current findings as baseline (run once after initial triage)
secureaudit baseline .

# Compare two runs — what changed?
secureaudit diff previous latest --db audits.db

# Scheduled audit (weekly, alert on regression)
secureaudit schedule . --cron "0 6 * * 1" --db audits.db --alert-webhook URL

# Install a pre-commit hook — blocks commits containing secrets
secureaudit pre-commit install

# Send a Slack alert with the scan summary
secureaudit scan . --alert-slack https://hooks.slack.com/services/...

# Weekly digest to Slack (run via your own cron, separate from `schedule`)
secureaudit digest . --db audits.db --slack-webhook https://hooks.slack.com/services/...

# Check/clear the incremental scan cache
secureaudit cache status .
secureaudit cache clear .

# Force a full rescan, bypassing the cache
secureaudit scan . --no-cache

# Group runs under a project (add 'project: my-app' to secureaudit.yml first)
secureaudit history --db audits.db --project my-app
secureaudit projects --db audits.db

# List available plugins
secureaudit list-plugins
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

### v1.3.0
- feat: project grouping — `project: name` in `secureaudit.yml` ties multiple repos/targets
  to one named project for portfolio-style aggregation — closes #20
  - `secureaudit history --db audits.db --project name` — filter CLI history by project
  - `secureaudit projects --db audits.db` — list all projects with latest score/grade
  - Dashboard: `GET /projects` (portfolio list) + `GET /projects/{name}` (score trend chart)
  - `GET /api/projects` and `GET /api/runs?project=name` JSON endpoints
  - Fully backward compatible: existing `audits.db` files migrate automatically (the `project`
    column is added via `ALTER TABLE` on first use); omitting `project:` keeps runs ungrouped
    exactly as before

### v1.2.0
- feat: incremental scan caching for `secrets`, `sast`, and `policy` (Dockerfile/CI checks) — closes #23
  - `.secureaudit-cache/` keyed by file content hash + plugin identity + plugin config hash
  - Unchanged files reuse cached results; a fully cache-hit SAST run never invokes `semgrep` at all
  - Changing a plugin's config in `secureaudit.yml` automatically invalidates affected entries
  - `--no-cache` forces a full rescan; `secureaudit cache status .` / `secureaudit cache clear .`
- fix: hard-excluded `.secureaudit-cache/` from all file-collecting plugins, independent of any
  user-configured `exclude_paths` — without this, the cache file (which stores matched secret
  evidence text) would be re-scanned as a *new* secret on every subsequent run, growing forever

### v1.1.0
- feat: native Slack notifications (`--alert-slack <webhook>`) — closes #21
  - Block Kit formatting: score, grade, severity counts, top 3 findings, colour-coded sidebar
  - Optional "View full report" button via `--dashboard-url`
- feat: native Microsoft Teams notifications (`--alert-teams <webhook>`) — closes #21
  - Equivalent Adaptive Card rendering
- feat: weekly digest mode — `secureaudit digest . --db audits.db --slack-webhook URL` — closes #21
  - Summarises N days of history: latest score/grade, 7-day trend, run count
- Colour coding (both platforms): 🟢 green ≥90, 🟡 yellow 60-89, 🔴 red <60
- `secureaudit schedule` now accepts `--alert-slack`/`--alert-teams` alongside the
  existing generic `--alert-webhook` — all fire only on score regression

### v1.0.9
- feat: published to PyPI — `pip install secureaudit` — closes #18
  - `.github/workflows/publish.yml` — auto-publish on `v*.*.*` tags via PyPI trusted publishing (OIDC, no stored token)
  - Optional extras: `secureaudit[sast]`, `secureaudit[dashboard]`, `secureaudit[all]`
- feat: Homebrew tap — `brew tap quaresma870/secureaudit && brew install secureaudit` — closes #18
  - New repo: [homebrew-secureaudit](https://github.com/quaresma870/homebrew-secureaudit)
  - Formula generated with real sha256 hashes for every Python dependency (fetched from PyPI's JSON API)
  - `bin/update-formula.sh` to bump the formula after each release
- fix: `pyproject.toml` had an invalid PEP 517 `build-backend`
  (`setuptools.backends.legacy:build` — not a real backend) that would have
  broken every `pip install`/`python -m build` attempt; corrected to `setuptools.build_meta`
  and verified end-to-end (built wheel → installed in clean venv → ran a real scan)
- fix: `secureaudit --version` was hardcoded to `"1.0.0"` regardless of the actual
  installed version; now resolves dynamically via `importlib.metadata`
- ci: added a `build` job that builds the package, runs `twine check`, and smoke-tests
  the installed CLI in a clean venv on every push — would have caught both bugs above

### v1.0.8
- feat: `secureaudit init` — interactive onboarding wizard — closes #19
  - Detects language (Python/Node/Go/Rust/PHP/Ruby), Dockerfile, git repo
  - Enables only relevant plugins: base (secrets/filesystem/policy) + cve if deps found,
    git_history if git repo, trivy if Dockerfile present
  - Optionally prompts for URLs (enables http/cors) and hosts (enables network)
  - `--yes` for non-interactive/CI use; `--force` to overwrite existing config
  - Offers to create a baseline immediately so day one isn't noisy

### v1.0.7
- feat: pre-commit hook — `secureaudit pre-commit install` — closes #24
  - Scans only staged files (fast — typically <1s, no full-repo walk)
  - Blocks commit if a CRITICAL/HIGH secret is detected, with clear remediation guidance
  - `secureaudit pre-commit uninstall` removes it cleanly; refuses to touch hooks it didn't install
  - `.pre-commit-hooks.yaml` published for compatibility with the [pre-commit framework](https://pre-commit.com)
  - `git commit --no-verify` documented as the (discouraged) override

### v1.0.6
- feat: `secureaudit diff <run1> <run2> --db audits.db` — closes #17
  - Matches findings across runs by stable key (plugin + rule + file), immune to line drift
  - Shows **new**, **resolved**, and unchanged-count
  - `latest`/`previous` keywords as shortcuts for run IDs
  - Non-zero exit code when new CRITICAL/HIGH findings are introduced (regression gate)
  - `--json` for CI consumption (e.g. PR comment bots)
  - `--include-suppressed` to also diff baselined/inline-suppressed findings

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

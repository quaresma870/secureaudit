# 🔐 SecureAudit

[![CI](https://github.com/quaresma870/secureaudit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/quaresma870/secureaudit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)
![Node.js](https://img.shields.io/badge/GitHub%20Actions-Node.js%2024-brightgreen?logo=nodedotjs&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

Multi-plugin security audit tool. Scans repositories and infrastructure for secrets, CVEs, misconfigurations, HTTP header issues, open ports and policy violations — producing a security score, HTML report and CI integration.

![SecureAudit dashboard showing a scan run with severity-tagged findings across multiple plugins](docs/images/dashboard.png)

*The `secureaudit serve` dashboard — real scan output, not a mockup: severity-tagged findings (AWS/API key detection, a root-running Dockerfile, an unpinned base image) with exact file:line locations.*

---

## Features

- ✅ **11 plugins** — secrets, CVE, filesystem, HTTP headers, network, policy, CORS, git history, SAST, malware, Trivy
- ✅ **Security score** 0–100 with letter grade (A–F)
- ✅ **Severity levels** — Critical / High / Medium / Low / Info
- ✅ **HTML report** — self-contained with Chart.js charts
- ✅ **JSON output** — machine-readable for integrations
- ✅ **SARIF 2.1.0 output** — validated against the official schema, wired into the GitHub Action for automatic Security tab integration
- ✅ **GitHub Action** — block PRs if score drops below threshold
- ✅ **Config file** — `secureaudit.yml` for full customisation
- ✅ **324 tests** — models, plugins, engine, dashboard, compliance, SARIF

---

## Plugins

| Plugin | What it checks |
|--------|---------------|
| `secrets` | API keys, tokens, passwords, private keys — regex + entropy filter. See [limitations note below](#secrets-plugin-limitations). |
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

### Secrets plugin limitations

Detection combines **regex patterns** (for well-known token shapes like AWS, GitHub, Stripe keys)
with an **entropy filter** (for generic high-randomness strings). This works well for the kinds of
secrets that actually appear in production breaches — real API keys and bearer tokens are
high-entropy by construction — but has predictable blind spots you should know about:

- **Low-entropy values are never flagged**, regardless of variable name. `PASSWORD = "hunter2"`,
  `DB_PASS = "changeme"`, or any value that looks like a human-chosen password will not be
  detected. The entropy threshold exists to avoid a flood of false positives on placeholder-looking
  values, but it means this is not a substitute for a policy rule on password patterns.
- **Context-free**: a high-entropy string in a comment, a test fixture, or a vendored file looks
  identical to a real credential. Suppression comments (`# secureaudit-ignore`) are the intended
  mechanism for known false positives.
- **No secrets manager integration**: values fetched at runtime from environment variables or
  secrets managers are not visible in a static scan — which is correct behaviour (they're not in
  the source), but means this tool cannot verify that you're *using* a secrets manager rather than
  hardcoding values in config files not covered by the scan target.

**Recommendation**: use this as one layer in a defense-in-depth approach. For the blind spots
above, a dedicated secrets-scanning tool (e.g. `trufflehog`, `detect-secrets`) with its own
pattern library for known low-entropy formats pairs well with this tool's broader posture scoring.

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

### Try it in one command

No config, no target project, no writing anything — scans a throwaway demo
project with real, deliberately planted findings and opens the dashboard:

```bash
pip install secureaudit[dashboard]
secureaudit demo
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

# Start the dashboard with REST API + OpenAPI docs at /docs
secureaudit serve --db audits.db
# Bound to a real network interface — requires a token for writes:
secureaudit serve --db audits.db --host 0.0.0.0 --token your-secret

# Control-by-control OWASP ASVS compliance breakdown
secureaudit scan . --compliance-report owasp-asvs
secureaudit scan . --compliance-report owasp-asvs --compliance-output compliance.json

# CIS Docker Benchmark (Section 4 — Dockerfile/build-file content, the
# part actually knowable from a repo checkout; the benchmark's other
# sections need a live Docker host to evaluate)
secureaudit scan . --compliance-report cis-docker

# PCI-DSS v4.0 (Requirement 6, partial — common software vulnerabilities
# via `sast`, and vulnerability identification via `cve`/`trivy`; the
# rest of Requirement 6 covers process/documentation this tool can't see)
secureaudit scan . --compliance-report pci-dss

# List available plugins
secureaudit list-plugins
```

### GitHub Action

Add to your workflow to audit every PR:

```yaml
permissions:
  contents: read
  security-events: write   # only needed if you use sarif-output below

steps:
  - name: Security Audit
    uses: quaresma870/secureaudit@main
    with:
      plugins: secrets,cve,filesystem,policy
      fail-below: "70"
      output-html: secureaudit-report.html
      output-json: secureaudit-report.json
      sarif-output: secureaudit.sarif   # findings show up in the Security tab automatically
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
│   ├── compliance/
│   │   ├── owasp_asvs.py       # OWASP ASVS v4.0.3 control-by-control mapping
│   │   ├── cis_docker.py       # CIS Docker Benchmark Section 4 mapping
│   │   └── pci_dss.py          # PCI-DSS v4.0 Requirement 6 (partial) mapping
│   ├── dashboard/
│   │   └── app.py              # FastAPI dashboard — history, projects, webhooks
│   └── reports/
│       ├── html.py             # Self-contained HTML with Chart.js
│       ├── json_report.py      # JSON serialiser
│       ├── sarif.py            # SARIF 2.1.0 — GitHub Security tab integration
│       └── terminal.py         # Rich terminal rendering — shared by `scan` and `schedule`
├── tests/
│   ├── test_secureaudit.py     # 272 tests
│   └── fixtures/
│       └── sarif-schema-2.1.0.json   # official schema, for real validation in tests
├── action.yml                  # GitHub Action definition
├── secureaudit.yml.example     # Config template
├── .github/workflows/ci.yml    # Lint + test pipeline
├── requirements.txt
└── pyproject.toml
```

---

## CI

On every push/PR: lint → unit tests (290+, mocked/isolated) → build the real
wheel, install it in a clean venv, and run a **real integration test** —
every README-documented command, against the actual installed CLI, in a
real test project: `init`, `scan` (several flag combinations), `baseline`,
`diff`, `digest`, `pre-commit install` followed by an actual `git commit`
with a real secret (confirmed blocked, with a deliberately stripped-down
`PATH` simulating a GUI git client or unactivated venv), `serve` (real HTTP
requests against the running dashboard), `schedule` (a real timed run,
confirming the immediate first job doesn't crash), both compliance
frameworks, and the cache/list-plugins commands.

This exists because five real bugs (`schedule` crashing on every
invocation, `digest` silently finding nothing for the most common usage
pattern, `serve` dumping a raw traceback, the pre-commit hook's PATH
fragility, and the fix for that last one's own error message) all shipped
past 290+ passing unit tests, because those tests exercise individual
functions and components in isolation — never the actual installed CLI a
real user runs. Confirmed this job actually catches a regression by
temporarily reintroducing one of those five bugs and watching it fail,
before relying on it.

---

## Running tests

```bash
PYTHONPATH=. pytest tests/ -v
```

---

See [CHANGELOG.md](CHANGELOG.md) for release history.

---

## License

MIT

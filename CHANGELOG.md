# Changelog

All notable changes to this project are documented here. See the
[README](README.md) for current features and usage.

### v1.6.5
- feat: **exhaustive per-plugin functional audit** — `cors`, `sast`, `malware`, `network`, and
  `http` plugins (the ones not exercised by the recent end-to-end command-level audit) run
  correctly end-to-end against a real test target, with confirmed graceful degradation when an
  external dependency (semgrep, clamav, trivy) genuinely isn't installed — closes #30. New
  `TestAllPluginsRunWithoutCrashing` includes a meta-test that loops every registered plugin
  through `AuditEngine.run()`, so a future new plugin gets this same coverage automatically.
- fix: restored `TestDocumentationFreshness` (#32), which had been unintentionally reverted by a
  `git checkout` used mid-session to undo an unrelated temporary test — caught by noticing it was
  simply absent from a subsequent test run's output, not by a failure. README's test count
  corrected to the current real 301.

### v1.6.4
- docs: **secrets plugin limitations** — documented the entropy-detection blind spots in the README: low-entropy values (human-chosen passwords) are never flagged by design, scanning is context-free (cannot distinguish a real key from one in a comment/fixture), and there is no secrets-manager-integration awareness — closes #33. Includes a concrete recommendation for complementary tooling (trufflehog, detect-secrets) to cover what this tool will not catch.
- feat: **publish pipeline — wheel content verification** — new step in publish.yml confirms all critical modules (including recently-added terminal.py, cis_docker.py, sarif.py, precommit.py, scheduler.py) are actually present inside the built wheel, not just in the source tree — closes #34.

### v1.6.3
- feat: **documentation freshness check** — `TestDocumentationFreshness` now runs on every `pytest` invocation, asserting the README's stated test count and plugin count match the real values, with a clear message pointing at the fix needed — closes #32. Confirmed to catch drift by temporarily adding a dummy test without updating the README.
- fix: README's test count updated from the stale 285 to the real 294 (9 tests added during the recent audit sprint were not reflected).

### v1.6.2
- feat: **CI integration-test tier** — extended the build job's minimal smoke test into a real
  integration test covering every README-documented command against the actual installed wheel in
  a fresh venv: `init`, `scan` (several flag combinations), `baseline`, `diff`, `digest`,
  `pre-commit install` followed by an actual `git commit` with a real secret under a deliberately
  stripped-down PATH, `serve` with real HTTP requests, `schedule` with a real timed run, both
  compliance frameworks, and `cache`/`list-plugins` — closes #31. None of the five bugs fixed in
  v1.6.1 were possible to catch with unit tests alone, which exercise individual functions in
  isolation, never the actual installed CLI a real user runs. Verified to actually catch a
  regression by temporarily reintroducing the v1.6.1 scheduler bug and confirming this job fails.

### v1.6.1
- fix: **`schedule` crashed on every single invocation** — `run_schedule()`'s job() imported from a
  module that has never existed anywhere in this codebase (`secureaudit.output.terminal`).
  Extracted the rendering logic into a real, shared `reports/terminal.py` that both `scan` and
  `schedule` import correctly. Found by building the real wheel, installing it in a clean venv, and
  running every command this README documents, literally as written — not caught by the existing
  test suite, which only tested the cron-parsing helper in isolation, never `run_schedule()` itself.
- fix: **`digest` silently found nothing** for the single most common usage pattern possible:
  `scan .` followed by `digest .` (this README's own lead example). `AuditEngine` resolves `target`
  to an absolute path before storing it; `digest` compared against the raw, unresolved CLI argument.
- fix: **`serve` dumped a raw traceback** if `uvicorn` was installed but `fastapi` wasn't — only one
  of the two was guarded. Both checked explicitly now, pointing at the real `secureaudit[dashboard]`
  extra — whose name had to be fixed *again* after the first attempt: Rich's console markup parser
  treats square brackets as tag syntax, silently stripping an unescaped `[dashboard]` from the
  visible output.
- fix: **the pre-commit hook could silently let secrets through** — the generated hook called bare
  `secureaudit pre-commit run`, trusting PATH resolution at commit time, which a real venv install +
  a GUI git client or fresh shell genuinely does not have. Now bakes in the absolute path to the
  specific installation doing the `pre-commit install`, resolved at install time.
- test: 8 new regression tests, each confirmed (by temporarily reverting its corresponding fix) to
  actually fail against the original broken code, not just pass against the fixed version.

### v1.6.0
- fix: **`action.yml` was broken YAML from the start** — an unquoted colon inside a plain-scalar
  description (`(default: all)`) made the entire file invalid YAML, confirmed against the version
  already on `dev` before touching anything. This means `uses: quaresma870/secureaudit@main`, as
  documented in this project's own README, could never have actually worked for anyone — GitHub
  can't parse the action's metadata file to discover its inputs/outputs/steps at all. Fixed by
  quoting the string — closes #27.
- feat: **`sarif-output` input added to the GitHub Action**, wired to the CLI's existing `--sarif`
  flag, plus a `github/codeql-action/upload-sarif@v4` step (the current recommended major version,
  not v3 which starts deprecating in Dec 2026) that runs on `always()` — the audit "failing" its
  score threshold is exactly the case where you most want findings visible in the Security tab,
  not less.
- fix: the `$schema` URL written into every generated SARIF file 404s — a known, widely-reported
  issue with the SARIF spec's own published examples, not unique to this codebase. Found the actual
  working path and confirmed it resolves before using it — closes #26.
- test: **5 new SARIF tests** — real schema validation against the official 2.1.0 schema (bundled
  in `tests/fixtures/`, not fetched live), a regression test pinning the corrected schema URL,
  correct omission of `locations` for findings with no file/line, severity-to-level mapping
  verified against actual written output, and rule deduplication.
- feat: **new `cis-docker` compliance framework** — `--compliance-report cis-docker` — mapping to
  CIS Docker Benchmark Section 4 (Container Images and Build File Configuration) specifically,
  confirmed against the real published control numbering (4.1, 4.2, 4.9, 4.10) before mapping
  anything. Deliberately scoped to Section 4 only: the benchmark's other sections need a live
  Docker host to evaluate, which is unobservable from static source — closes #28.
- fix: `--compliance-report`'s `click.Choice()` was hardcoded to `["owasp-asvs"]` rather than
  derived from the `FRAMEWORKS` registry — registering a new framework there alone would not have
  made it reachable through the CLI at all. Now derives the choice list dynamically.
- test: **13 new CIS Docker tests**, including one that caught a real bug in the first version of
  `evaluate()`: an attempt to mark "no Dockerfile found" as `NOT_APPLICABLE` couldn't distinguish
  that from "a Dockerfile exists and is fully compliant" — a clean Dockerfile was incorrectly
  showing `NOT_APPLICABLE` instead of `PASS` until actually running it against one caught this and
  it was simplified to match `owasp_asvs.py`'s proven convention.
- fix: swapped `httpx` for `httpx2` in requirements.txt — the exact same Starlette/FastAPI
  `TestClient` deprecation that became a hard `RuntimeError` in a sibling portfolio repo, applied
  here proactively before it does the same.
- docs: fixed several README staleness issues found along the way — the plugin count summary said
  "6 plugins" when 11 actually exist, the test count was stale at several points as tests were
  added through this release (25 → 285), and the project structure tree was missing `sarif.py`,
  `compliance/`, `dashboard/`, and `tests/fixtures/` entirely.

### v1.5.0
- feat: OWASP ASVS v4.0.3 compliance mapping — `--compliance-report owasp-asvs` — closes #22
  - 15 ASVS controls mapped across 9 plugins (secrets, cve, trivy, http, cors, sast, policy,
    malware, git_history) — control-by-control PASS / FAIL / NOT_APPLICABLE breakdown
  - `--compliance-output path.json` for a machine-readable export
  - **Best-effort mapping, not a certification tool** — requirement descriptions are paraphrased
    summaries; verify against the official standard before relying on this for a real audit:
    https://github.com/OWASP/ASVS/tree/master/4.0
  - A control is `NOT_APPLICABLE` when none of the plugins that could provide evidence for it
    were run in this scan; `PASS` means the relevant plugin(s) ran clean, not that every aspect
    of the requirement was independently verified
  - Suppressed/baselined findings never count as compliance failures, consistent with how they're
    excluded from the security score

### v1.4.0
- feat: REST API for the dashboard — closes #25
  - `POST /api/scan` — triggers a scan asynchronously, returns a `scan_id` immediately;
    poll `GET /api/scan/{scan_id}` for `running` → `completed`/`failed` + the resulting run ID
  - `POST /api/projects/{name}/webhooks` — register a webhook that fires when a project's new
    run introduces new CRITICAL/HIGH findings vs. its previous run (reuses the `diff` engine);
    `GET`/`DELETE` to list/remove
  - `GET /api/runs/{id}/findings?severity=CRITICAL` — filterable findings endpoint
  - API token auth (`Authorization: Bearer <token>`) — required for all POST/DELETE endpoints
    once the dashboard is bound to anything other than localhost; `secureaudit serve --token`
    or `SECUREAUDIT_API_TOKEN` env var, auto-generated and printed if needed and not provided
  - OpenAPI docs enabled at `/docs` (and `/redoc`)
  - `scan`/`schedule` CLI commands now fire registered project webhooks automatically after
    saving to history, same regression-diff logic as the dashboard's background scan

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

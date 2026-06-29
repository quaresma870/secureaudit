"""
SecureAudit CLI.
"""

from __future__ import annotations

import importlib.metadata
import sys
from datetime import UTC
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.table import Table

from secureaudit.compliance import FRAMEWORKS
from secureaudit.core.config import load_config
from secureaudit.core.engine import AuditEngine
from secureaudit.core.models import Severity
from secureaudit.plugins import available_plugins
from secureaudit.reports.terminal import print_summary

console = Console()

try:
    __version__ = importlib.metadata.version("secureaudit")
except importlib.metadata.PackageNotFoundError:
    __version__ = "0.0.0+dev"  # running from source without pip install -e .

_SEV_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


@click.group()
@click.version_option(__version__, prog_name="secureaudit")
def cli():
    """🔐 SecureAudit — multi-plugin security audit tool."""


@cli.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--yes", "-y", is_flag=True, help="Skip interactive prompts; auto-detect only.")
@click.option("--force", is_flag=True, help="Overwrite an existing secureaudit.yml.")
@click.option("--baseline/--no-baseline", default=None,
              help="Create a baseline immediately after writing config. Prompts if not set.")
def init(target, yes, force, baseline):
    """Interactive setup wizard — detects your stack and writes a tailored secureaudit.yml."""
    from secureaudit.core.init import build_config, detect_project, write_config

    target_path = Path(target)
    config_path = target_path / "secureaudit.yml"

    if config_path.exists() and not force:
        console.print(f"[yellow]{config_path} already exists.[/yellow] Use --force to overwrite.")
        sys.exit(1)

    console.print()
    console.rule("[bold cyan]🔐 SecureAudit Setup[/bold cyan]")
    console.print(f"\n[dim]Scanning project structure in[/dim] [green]{target}[/green]...\n")

    detection = detect_project(target_path)

    if detection["languages"]:
        console.print(f"  [green]✔[/green] Detected: {', '.join(detection['languages'])}")
    else:
        console.print("  [yellow]⚠[/yellow]  No recognised dependency manifest found")
    if detection["has_dockerfile"]:
        console.print("  [green]✔[/green] Dockerfile found → enabling trivy (container/IaC scan)")
    if detection["has_git"]:
        console.print("  [green]✔[/green] Git repository found → enabling git_history")

    urls: list[str] = []
    hosts: list[str] = []

    if not yes:
        console.print()
        if click.confirm("Do you have live URLs to check (HTTP headers, CORS)?", default=False):
            raw = click.prompt("Enter URLs, comma-separated")
            urls = [u.strip() for u in raw.split(",") if u.strip()]

        if click.confirm("Do you have hosts to check for exposed ports?", default=False):
            raw = click.prompt("Enter hosts, comma-separated")
            hosts = [h.strip() for h in raw.split(",") if h.strip()]

    config = build_config(detection, urls=urls or None, hosts=hosts or None)
    write_config(config_path, config)

    console.print(f"\n[green]✔[/green] Config written: [bold]{config_path}[/bold]")
    console.print(f"  Plugins enabled: {', '.join(config['plugins'])}\n")

    do_baseline = baseline
    if do_baseline is None:
        do_baseline = yes or click.confirm(
            "Create a baseline now? (accepts current findings so day one isn't noisy)",
            default=True,
        )

    if do_baseline:
        from secureaudit.core.baseline import default_baseline_path, save_baseline
        from secureaudit.core.config import load_config as _load_cfg
        from secureaudit.core.engine import AuditEngine

        console.print("\n[dim]Running initial scan to build baseline...[/dim]")
        cfg = _load_cfg(config_path)
        engine = AuditEngine(cfg)
        result = engine.run(target_path)
        bpath = default_baseline_path(target_path)
        count = save_baseline(bpath, result.all_findings, str(target_path))
        console.print(f"[green]✔[/green] Baseline saved: [bold]{bpath}[/bold] ({count} finding(s) accepted)")

    console.print("\n[bold]Next steps:[/bold]")
    console.print("  [cyan]secureaudit scan .[/cyan]              — run a scan")
    console.print("  [cyan]secureaudit pre-commit install[/cyan]  — block commits with secrets")
    console.print()


@cli.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--config", "-c", default=None, help="Path to secureaudit.yml")
@click.option("--plugins", "-p", default=None, help="Comma-separated list of plugins to run")
@click.option("--output", "-o", default=None, help="Write HTML report to file")
@click.option("--json", "json_out", default=None, help="Write JSON report to file")
@click.option("--sarif", "sarif_out", default=None, help="Write SARIF 2.1.0 report to file")
@click.option("--db", default=None, help="SQLite database to persist results for history")
@click.option("--fail-below", default=None, type=int, help="Exit 1 if score below threshold")
@click.option("--no-terminal", is_flag=True, help="Suppress terminal output")
@click.option("--baseline-file", default=None,
              help="Path to baseline file (default: <target>/.secureaudit-baseline.json if present)")
@click.option("--no-baseline", is_flag=True, help="Ignore baseline file even if present")
@click.option("--no-inline-suppress", is_flag=True, help="Ignore inline 'secureaudit-ignore' comments")
@click.option("--alert-slack", default=None, help="Slack incoming webhook URL — sends a Block Kit summary")
@click.option("--alert-teams", default=None, help="Teams incoming webhook URL — sends an Adaptive Card summary")
@click.option("--dashboard-url", default=None, help="Link included in Slack/Teams messages (e.g. dashboard run URL)")
@click.option("--no-cache", is_flag=True,
              help="Disable incremental file-result caching — forces a full rescan of every file.")
@click.option("--compliance-report", default=None,
              type=click.Choice(list(FRAMEWORKS.keys())),
              help="Show a control-by-control compliance breakdown for the given framework.")
@click.option("--compliance-output", default=None,
              help="Write the compliance breakdown as JSON to this path.")
def scan(
    target, config, plugins, output, json_out, sarif_out, db, fail_below,
    no_terminal, baseline_file, no_baseline, no_inline_suppress,
    alert_slack, alert_teams, dashboard_url, no_cache,
    compliance_report, compliance_output,
):
    """Run a security audit on TARGET (default: current directory)."""

    cfg = load_config(config or Path(target) / "secureaudit.yml")
    plugin_list = [p.strip() for p in plugins.split(",")] if plugins else None
    threshold = fail_below if fail_below is not None else cfg.fail_below

    if not no_terminal:
        console.print()
        console.rule("[bold cyan]🔐 SecureAudit[/bold cyan]")
        console.print(f"\n  [dim]Target:[/dim] [green]{target}[/green]")
        plugin_names = plugin_list or cfg.plugins
        console.print(f"  [dim]Plugins:[/dim] {', '.join(plugin_names)}\n")

    cache = None
    if not no_cache:
        from secureaudit.core.cache import FileCache, default_cache_path
        cache = FileCache(default_cache_path(target))

    engine = AuditEngine(cfg, cache=cache)
    result = engine.run(target, plugin_list)

    if cache is not None:
        cache.save()

    # ── Baseline + inline suppression ───────────────────────────────────────
    from secureaudit.core.baseline import apply_suppressions, default_baseline_path

    bpath = None
    if not no_baseline:
        bpath = Path(baseline_file) if baseline_file else default_baseline_path(target)
        if not bpath.exists():
            bpath = None

    apply_suppressions(
        result,
        target=Path(target),
        baseline_path=bpath,
        exclude_paths=set(cfg.exclude_paths),
        check_inline=not no_inline_suppress,
    )

    if not no_terminal:
        print_summary(result, threshold)

    if compliance_report:
        rows = FRAMEWORKS[compliance_report](result)
        if not no_terminal:
            _print_compliance(rows, compliance_report)
        if compliance_output:
            import json as _json
            Path(compliance_output).write_text(_json.dumps(rows, indent=2))
            console.print(f"[green]✔[/green] Compliance report: [bold]{compliance_output}[/bold]")

    if output:
        from secureaudit.reports.html import write_html
        write_html(result, output)
        console.print(f"[green]✔[/green] HTML report: [bold]{output}[/bold]")

    if json_out:
        from secureaudit.reports.json_report import write_json
        write_json(result, json_out)
        console.print(f"[green]✔[/green] JSON report: [bold]{json_out}[/bold]")

    if sarif_out:
        from secureaudit.reports.sarif import write_sarif
        write_sarif(result, sarif_out)
        console.print(f"[green]✔[/green] SARIF report: [bold]{sarif_out}[/bold]")

    if alert_slack:
        from secureaudit.notifications import send_slack
        ok = send_slack(alert_slack, result, dashboard_url)
        console.print("[green]✔[/green] Slack notification sent" if ok
                      else "[yellow]⚠  Slack notification failed[/yellow]")

    if alert_teams:
        from secureaudit.notifications import send_teams
        ok = send_teams(alert_teams, result, dashboard_url)
        console.print("[green]✔[/green] Teams notification sent" if ok
                      else "[yellow]⚠  Teams notification failed[/yellow]")

    if db:
        from secureaudit.reports.history import save
        run_id = save(result, db, project=cfg.project)
        console.print(f"[green]✔[/green] Saved to [bold]{db}[/bold] (run #{run_id})")

        if cfg.project:
            from secureaudit.core.webhooks import check_and_fire_project_webhooks
            fired = check_and_fire_project_webhooks(db, cfg.project, run_id)
            if fired:
                console.print(f"[yellow]🔔 {fired} webhook(s) notified — new regression detected[/yellow]")

    if result.score < threshold:
        console.print(f"\n[bold red]✘ Score {result.score} is below threshold {threshold}. Failing.[/bold red]\n")
        sys.exit(1)


@cli.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--config", "-c", default=None, help="Path to secureaudit.yml")
@click.option("--plugins", "-p", default=None, help="Comma-separated list of plugins to run")
@click.option("--baseline-file", default=None,
              help="Path to write baseline (default: <target>/.secureaudit-baseline.json)")
@click.option("--force", is_flag=True, help="Replace baseline entirely instead of merging")
def baseline(target, config, plugins, baseline_file, force):
    """Snapshot current findings as an accepted baseline.

    Findings present in the baseline are suppressed (but still visible,
    labelled 'baseline') in future scans. Run this once after triaging
    existing findings you've decided are acceptable risk or false positives.
    """
    from secureaudit.core.baseline import default_baseline_path, save_baseline

    cfg = load_config(config or Path(target) / "secureaudit.yml")
    plugin_list = [p.strip() for p in plugins.split(",")] if plugins else None

    console.print(f"\n[dim]Scanning[/dim] [green]{target}[/green] [dim]to build baseline...[/dim]\n")
    engine = AuditEngine(cfg)
    result = engine.run(target, plugin_list)

    path = Path(baseline_file) if baseline_file else default_baseline_path(target)
    count = save_baseline(path, result.all_findings, str(target), merge=not force)

    console.print(f"[green]✔[/green] Baseline saved: [bold]{path}[/bold] ({count} finding(s) accepted)")
    console.print("[dim]Future scans will suppress these findings (shown separately, not hidden).[/dim]\n")


@cli.command()
@click.argument("run1")
@click.argument("run2")
@click.option("--db", required=True, help="SQLite database with audit history.")
@click.option("--include-suppressed", is_flag=True,
              help="Include suppressed findings in the comparison.")
@click.option("--json", "json_out", is_flag=True, help="Output as JSON instead of a table.")
def diff(run1, run2, db, include_suppressed, json_out):
    """Compare findings between two scan runs.

    RUN1 and RUN2 may be numeric run IDs, or the keywords 'latest'/'previous'.

    Examples:
      secureaudit diff 12 15 --db audits.db
      secureaudit diff previous latest --db audits.db
    """
    from secureaudit.core.diff import diff_runs, resolve_run_id

    if not Path(db).exists():
        console.print(f"[red]Database not found: {db}[/red]")
        sys.exit(1)

    try:
        id1 = resolve_run_id(db, run1)
        id2 = resolve_run_id(db, run2)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)

    result = diff_runs(db, id1, id2, include_suppressed=include_suppressed)

    if json_out:
        import json as _json
        console.print(_json.dumps(result.to_dict(), indent=2))
    else:
        _print_diff(result)

    if result.has_new_regression:
        sys.exit(1)


@cli.command(name="list-plugins")
def list_plugins():
    """List all available plugins."""
    console.print("\n[bold]Available plugins:[/bold]\n")
    descriptions = {
        "secrets": "Detect exposed API keys, tokens and passwords",
        "cve": "Check dependencies for known CVEs (OSV.dev)",
        "filesystem": "File permissions, SUID bits, sensitive committed files",
        "http": "HTTP security headers, SSL/TLS, redirects",
        "network": "Port scan for exposed services",
        "policy": ".gitignore completeness, Dockerfile security, CI hardening",
        "cors": "CORS misconfiguration — origin reflection, wildcard + credentials",
        "git_history": "Scan git history for secrets removed from working tree",
        "sast": "Static code analysis for vulnerability patterns (requires semgrep)",
        "malware": "Known malware signature scanning (requires clamav)",
        "trivy": "Container/filesystem CVEs + IaC misconfig (requires trivy)",
    }
    for name in available_plugins():
        desc = descriptions.get(name, "")
        console.print(f"  [cyan]{name:<12}[/cyan] {desc}")
    console.print()





@cli.command()
@click.option("--db", default="audits.db", show_default=True,
              help="SQLite database with audit history.")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8080, show_default=True)
@click.option("--token", default=None,
              help="API token required for write operations (POST/DELETE). "
                   "Auto-generated and printed if the dashboard isn't bound to "
                   "localhost and no token was provided. Also reads SECUREAUDIT_API_TOKEN.")
def serve(db, host, port, token):
    """Start the web dashboard for audit history."""
    try:
        # fastapi is imported here too, not left for dashboard.app's own
        # import to surface — confirmed by actually reproducing this
        # exact failure (uvicorn present, fastapi absent) and getting a
        # raw, unhandled ModuleNotFoundError traceback instead of this
        # same clean message, before adding the explicit check.
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
    except ImportError:
        console.print("[red]Dashboard dependencies missing.[/red]")
        console.print("Install with: pip install 'secureaudit\\[dashboard]'")
        sys.exit(1)

    import os
    import secrets as _secrets

    from secureaudit.dashboard.app import create_app

    is_localhost = host in ("127.0.0.1", "localhost", "::1")
    require_token = not is_localhost

    if token is None:
        token = os.environ.get("SECUREAUDIT_API_TOKEN")

    if require_token and not token:
        token = _secrets.token_urlsafe(24)
        console.print(
            f"[yellow]⚠  Dashboard bound to {host} (not localhost) — generated an API token:[/yellow]"
        )
        console.print(f"  [bold]{token}[/bold]")
        console.print(
            "  Required for POST/DELETE requests: Authorization: Bearer <token>\n"
            "  (or set SECUREAUDIT_API_TOKEN to provide your own ahead of time)\n"
        )

    console.print(f"[bold cyan]🔐 SecureAudit Dashboard[/bold cyan] → http://{host}:{port}")
    console.print(f"[dim]API docs:[/dim] http://{host}:{port}/docs\n")

    app = create_app(db, api_token=token, require_token=require_token)
    uvicorn.run(app, host=host, port=port, log_level="warning")



@cli.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--cron", required=True,
              help='Cron expression e.g. "*/30 * * * *" or "0 6 * * 1".')
@click.option("--config", "-c", default=None, help="Path to secureaudit.yml")
@click.option("--plugins", "-p", default=None,
              help="Comma-separated plugins (default: all)")
@click.option("--db", default=None, help="SQLite database for history.")
@click.option("--alert-webhook", default=None,
              help="Generic webhook URL — only called on score regression.")
@click.option("--alert-slack", default=None,
              help="Slack incoming webhook URL — Block Kit summary, only on regression.")
@click.option("--alert-teams", default=None,
              help="Teams incoming webhook URL — Adaptive Card summary, only on regression.")
@click.option("--dashboard-url", default=None,
              help="Link included in Slack/Teams alerts (e.g. dashboard run URL).")
@click.option("--fail-below", default=70, show_default=True,
              help="Alert if score drops below this threshold.")
@click.option("--output-dir", default=None,
              help="Directory to write HTML reports per run.")
def schedule(
    target, cron, config, plugins, db, alert_webhook, alert_slack, alert_teams,
    dashboard_url, fail_below, output_dir,
):
    """Run security audits on a cron schedule.

    Runs immediately on start, then repeats per cron expression.
    Alerts only when score drops (regression detection — no false positives on stable repos).
    """
    try:
        import schedule as _s  # noqa: F401
    except ImportError:
        console.print("[red]Install schedule: pip install schedule[/red]")
        sys.exit(1)

    from secureaudit.scheduler import run_schedule
    plugin_list = [p.strip() for p in plugins.split(",")] if plugins else None
    run_schedule(
        target=target,
        cron_expr=cron,
        plugins=plugin_list,
        db=db,
        alert_webhook=alert_webhook,
        alert_slack=alert_slack,
        alert_teams=alert_teams,
        dashboard_url=dashboard_url,
        fail_below=fail_below,
        output_dir=output_dir,
        config_path=config,
    )


@cli.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--db", required=True, help="SQLite database with audit history.")
@click.option("--days", default=7, show_default=True, help="Number of days to summarise.")
@click.option("--slack-webhook", default=None, help="Slack incoming webhook URL for the digest.")
def digest(target, db, days, slack_webhook):
    """Send a weekly (or N-day) digest summarising recent scan history.

    Designed to be run on its own schedule (e.g. a weekly cron job calling
    this command), separate from the per-run regression alerts in `schedule`.
    """
    from datetime import datetime, timedelta

    from secureaudit.reports.history import get_runs

    if not Path(db).exists():
        console.print(f"[red]Database not found: {db}[/red]")
        sys.exit(1)

    cutoff = datetime.now(UTC) - timedelta(days=days)
    all_runs = get_runs(db, limit=200)
    # AuditEngine resolves target to an absolute path before it's ever
    # stored (core/engine.py) — comparing against the raw CLI argument
    # ("." being the overwhelmingly common case, exactly what this
    # project's own README leads with) would silently match nothing.
    # Reproduced this for real before fixing it: `scan .` then
    # `digest .` printed "printing digest instead" followed by zero
    # actual rows, not an error — just silently wrong.
    resolved_target = str(Path(target).resolve())
    runs = [r for r in all_runs if r["target"] == resolved_target]
    runs = [r for r in runs if datetime.fromisoformat(r["timestamp"]) >= cutoff] or runs[:1]

    if not slack_webhook:
        console.print("[yellow]No --slack-webhook provided — printing digest instead.[/yellow]\n")
        for r in runs[:5]:
            console.print(f"  #{r['id']}  {r['timestamp'][:16]}  score={r['score']} grade={r['grade']}")
        return

    from secureaudit.notifications import send_slack_digest
    ok = send_slack_digest(slack_webhook, runs, target)
    if ok:
        console.print(f"[green]✔[/green] Digest sent ({len(runs)} run(s) over the last {days} days)")
    else:
        console.print("[yellow]⚠  Digest send failed[/yellow]")
        sys.exit(1)


@cli.group(name="pre-commit")
def pre_commit_group():
    """Manage the git pre-commit hook that blocks commits containing secrets."""


@pre_commit_group.command(name="install")
@click.option("--force", is_flag=True, help="Overwrite an existing pre-commit hook.")
def pre_commit_install(force):
    """Install the secrets-scanning pre-commit hook in the current git repository."""
    from secureaudit.core.precommit import get_git_root, install_hook

    root = get_git_root()
    if root is None:
        console.print("[red]Not inside a git repository.[/red]")
        sys.exit(1)

    ok, msg = install_hook(root, force=force)
    if ok:
        console.print(f"[green]✔[/green] Installed: [bold]{msg}[/bold]")
        console.print("[dim]Staged files are scanned for secrets before each commit.[/dim]\n")
    else:
        console.print(f"[red]{msg}[/red]")
        sys.exit(1)


@pre_commit_group.command(name="uninstall")
def pre_commit_uninstall():
    """Remove the secureaudit pre-commit hook."""
    from secureaudit.core.precommit import get_git_root, uninstall_hook

    root = get_git_root()
    if root is None:
        console.print("[red]Not inside a git repository.[/red]")
        sys.exit(1)

    ok, msg = uninstall_hook(root)
    if ok:
        console.print(f"[green]✔[/green] Removed: [bold]{msg}[/bold]")
    else:
        console.print(f"[yellow]{msg}[/yellow]")


@pre_commit_group.command(name="run")
def pre_commit_run():
    """Internal — invoked by the installed git hook. Scans staged files for secrets."""
    from secureaudit.core.precommit import get_git_root, run_staged_scan

    root = get_git_root()
    if root is None:
        sys.exit(0)  # not a git repo somehow — never block on our own confusion
    sys.exit(run_staged_scan(root))


@cli.group()
def cache():
    """Manage the incremental scan cache (.secureaudit-cache/)."""


@cache.command(name="clear")
@click.argument("target", default=".", type=click.Path(exists=True))
def cache_clear(target):
    """Delete the incremental scan cache for TARGET, forcing a full rescan next time."""
    from secureaudit.core.cache import default_cache_path

    path = default_cache_path(target)
    if path.exists():
        path.unlink()
        # Remove the directory too if now empty
        try:
            path.parent.rmdir()
        except OSError:
            pass
        console.print(f"[green]✔[/green] Cache cleared: [bold]{path}[/bold]")
    else:
        console.print(f"[yellow]No cache found at {path}[/yellow]")


@cache.command(name="status")
@click.argument("target", default=".", type=click.Path(exists=True))
def cache_status(target):
    """Show cache entry count and file size for TARGET."""
    from secureaudit.core.cache import FileCache, default_cache_path

    path = default_cache_path(target)
    if not path.exists():
        console.print(f"[yellow]No cache found at {path}[/yellow]")
        return

    c = FileCache(path)
    size_kb = path.stat().st_size / 1024
    console.print(f"[bold]Cache:[/bold] {path}")
    console.print(f"  Entries: {c.entry_count}")
    console.print(f"  Size: {size_kb:.1f} KB")


@cli.command()
@click.option("--db", required=True, help="SQLite database with audit history.")
@click.option("--project", default=None, help="Only show runs belonging to this project.")
@click.option("--limit", default=20, show_default=True, help="Number of runs to show.")
def history(db, project, limit):
    """Show recent scan runs from history, optionally filtered by --project."""
    from secureaudit.reports.history import get_runs

    if not Path(db).exists():
        console.print(f"[red]Database not found: {db}[/red]")
        sys.exit(1)

    runs = get_runs(db, limit=limit, project=project)
    if not runs:
        msg = f"No runs found for project '{project}'." if project else "No runs recorded yet."
        console.print(f"[yellow]{msg}[/yellow]")
        return

    title = f"History — project: {project}" if project else "History"
    t = Table(title=title, box=box.SIMPLE_HEAD)
    t.add_column("#", width=6)
    t.add_column("Target", overflow="fold")
    t.add_column("Project")
    t.add_column("Timestamp")
    t.add_column("Score", justify="right")
    t.add_column("Grade")
    t.add_column("Crit+High", justify="right")
    for r in runs:
        score_color = "green" if r["score"] >= 90 else "yellow" if r["score"] >= 60 else "red"
        t.add_row(
            str(r["id"]), r["target"], r["project"] or "[dim]—[/dim]", r["timestamp"][:16],
            f"[{score_color}]{r['score']}[/]", r["grade"], str(r["critical_high"]),
        )
    console.print(t)


@cli.command()
@click.option("--db", required=True, help="SQLite database with audit history.")
def projects(db):
    """List all named projects with their latest score — a portfolio overview."""
    from secureaudit.reports.history import get_project_run_count, get_projects

    if not Path(db).exists():
        console.print(f"[red]Database not found: {db}[/red]")
        sys.exit(1)

    rows = get_projects(db)
    if not rows:
        console.print(
            "[yellow]No projects found.[/yellow] Add 'project: name' to secureaudit.yml "
            "and run a scan with --db to start grouping runs."
        )
        return

    t = Table(title="Projects", box=box.SIMPLE_HEAD)
    t.add_column("Project")
    t.add_column("Latest Score", justify="right")
    t.add_column("Grade")
    t.add_column("Runs", justify="right")
    t.add_column("Last scan")
    for r in rows:
        score_color = "green" if r["score"] >= 90 else "yellow" if r["score"] >= 60 else "red"
        run_count = get_project_run_count(db, r["project"])
        t.add_row(
            r["project"], f"[{score_color}]{r['score']}[/]", r["grade"],
            str(run_count), r["timestamp"][:16],
        )
    console.print(t)


_FRAMEWORK_DISPLAY_NAMES = {
    "owasp-asvs": "OWASP ASVS v4.0.3",
    "cis-docker": "CIS Docker Benchmark (Section 4)",
}

_COMPLIANCE_STATUS_COLOR = {
    "PASS": "green",
    "FAIL": "red",
    "NOT_APPLICABLE": "dim",
}


def _print_compliance(rows: list[dict], framework: str) -> None:
    display_name = _FRAMEWORK_DISPLAY_NAMES.get(framework, framework)
    console.print()
    console.rule(f"[bold cyan]Compliance: {display_name}[/bold cyan]")
    console.print(
        "[dim]Best-effort mapping — not a substitute for a full assessment. "
        "Verify against the official standard before relying on this for an audit.[/dim]\n"
    )

    t = Table(box=box.SIMPLE_HEAD, show_lines=True)
    t.add_column("Control", no_wrap=True)
    t.add_column("Chapter", overflow="fold")
    t.add_column("Status", no_wrap=True)
    t.add_column("Description", overflow="fold", ratio=2)
    t.add_column("Evidence", justify="right", no_wrap=True)

    counts = {"PASS": 0, "FAIL": 0, "NOT_APPLICABLE": 0}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
        color = _COMPLIANCE_STATUS_COLOR.get(row["status"], "white")
        t.add_row(
            row["id"], row["chapter"], f"[{color}]{row['status']}[/]",
            row["description"], str(row["evidence_count"]),
        )
    console.print(t)
    console.print(
        f"\n[green]{counts['PASS']} PASS[/green]  "
        f"[red]{counts['FAIL']} FAIL[/red]  "
        f"[dim]{counts['NOT_APPLICABLE']} N/A[/dim]\n"
    )


def _print_diff(result) -> None:
    console.print()
    console.rule(f"[bold cyan]Diff: run #{result.run1_id} → run #{result.run2_id}[/bold cyan]")
    console.print()

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    if result.new:
        t = Table(title=f"🆕 New findings ({len(result.new)})", box=box.SIMPLE_HEAD, border_style="red")
        t.add_column("Severity")
        t.add_column("Plugin")
        t.add_column("Title", overflow="fold")
        t.add_column("File", overflow="fold")
        for f in sorted(result.new, key=lambda x: sev_order.index(x["severity"])):
            color = _SEV_COLOR.get(Severity(f["severity"]), "white")
            t.add_row(f"[{color}]{f['severity']}[/]", f["plugin"], f["title"], f.get("file") or "")
        console.print(t)
    else:
        console.print("[green]No new findings.[/green]")

    if result.resolved:
        t = Table(title=f"✅ Resolved findings ({len(result.resolved)})", box=box.SIMPLE_HEAD, border_style="green")
        t.add_column("Severity")
        t.add_column("Plugin")
        t.add_column("Title", overflow="fold")
        t.add_column("File", overflow="fold")
        for f in sorted(result.resolved, key=lambda x: sev_order.index(x["severity"])):
            t.add_row(f["severity"], f["plugin"], f["title"], f.get("file") or "")
        console.print(t)

    console.print(f"\n[dim]{result.unchanged_count} unchanged finding(s).[/dim]")

    if result.has_new_regression:
        console.print("\n[bold red]✘ Regression: new CRITICAL/HIGH findings introduced.[/bold red]\n")
    else:
        console.print("\n[green]✔ No regression.[/green]\n")


def main():
    cli()


if __name__ == "__main__":
    main()

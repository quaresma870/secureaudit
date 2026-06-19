"""
SecureAudit CLI.
"""

from __future__ import annotations

import importlib.metadata
import sys
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from secureaudit.core.config import load_config
from secureaudit.core.engine import AuditEngine
from secureaudit.core.models import Severity
from secureaudit.plugins import available_plugins

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
def scan(
    target, config, plugins, output, json_out, sarif_out, db, fail_below,
    no_terminal, baseline_file, no_baseline, no_inline_suppress,
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

    engine = AuditEngine(cfg)
    result = engine.run(target, plugin_list)

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
        _print_result(result, threshold)

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

    if db:
        from secureaudit.reports.history import save
        run_id = save(result, db)
        console.print(f"[green]✔[/green] Saved to [bold]{db}[/bold] (run #{run_id})")

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


def _print_result(result, threshold: int) -> None:
    score = result.score
    grade = result.grade
    counts = result.counts_by_severity()

    score_color = "red" if score < 60 else "yellow" if score < 75 else "green"
    status = "✘ FAIL" if score < threshold else "✔ PASS"
    status_color = "red" if score < threshold else "green"
    suppressed_line = ""
    if result.suppressed_findings:
        suppressed_line = f"\n[dim]🔇 {len(result.suppressed_findings)} suppressed (baseline/inline — not counted in score)[/dim]"

    # Score panel
    console.print(Panel(
        f"[{score_color}][bold]{score}/100[/bold][/{score_color}]  Grade [{score_color}]{grade}[/{score_color}]"
        f"  [{status_color}]{status}[/{status_color}]  "
        f"[dim](threshold: {threshold})[/dim]\n"
        f"[bold red]■[/bold red] {counts.get('CRITICAL',0)} Critical  "
        f"[red]■[/red] {counts.get('HIGH',0)} High  "
        f"[yellow]■[/yellow] {counts.get('MEDIUM',0)} Medium  "
        f"[blue]■[/blue] {counts.get('LOW',0)} Low  "
        f"[dim]■[/dim] {counts.get('INFO',0)} Info"
        f"{suppressed_line}",
        title="Security Score",
        border_style=score_color,
    ))

    # Plugin summary
    t = Table(title="Plugin Results", box=box.SIMPLE_HEAD)
    t.add_column("Plugin", style="cyan")
    t.add_column("Score", justify="right")
    t.add_column("Findings", justify="right")
    t.add_column("Status")
    t.add_column("Duration")
    for pr in result.plugin_results:
        status_str = "[red]✘ FAIL[/red]" if not pr.passed else "[green]✔ PASS[/green]"
        if pr.error:
            status_str = "[yellow]⚠ ERROR[/yellow]"
        t.add_row(
            pr.plugin,
            f"[{'green' if pr.score >= 80 else 'yellow' if pr.score >= 60 else 'red'}]{pr.score}[/]",
            str(len(pr.findings)),
            status_str,
            f"{pr.duration_ms:.0f}ms",
        )
    console.print(t)

    # Findings (non-INFO)
    findings = [f for f in result.all_findings if f.severity != Severity.INFO]
    if findings:
        t2 = Table(title="Findings", box=box.SIMPLE_HEAD, show_lines=True)
        t2.add_column("Sev", width=10)
        t2.add_column("Plugin", width=12)
        t2.add_column("Title", overflow="fold")
        t2.add_column("File", overflow="fold", width=30)
        for f in sorted(findings, key=lambda x: list(Severity).index(x.severity)):
            color = _SEV_COLOR.get(f.severity, "white")
            file_str = f.file or ""
            if f.line:
                file_str += f":{f.line}"
            t2.add_row(
                f"[{color}]{f.severity.value}[/]",
                f.plugin,
                f.title,
                file_str,
            )
        console.print(t2)
    else:
        console.print("[green]  No significant findings.[/green]\n")



@cli.command()
@click.option("--db", default="audits.db", show_default=True,
              help="SQLite database with audit history.")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8080, show_default=True)
def serve(db, host, port):
    """Start the web dashboard for audit history."""
    try:
        import uvicorn
    except ImportError:
        console.print("[red]uvicorn is required: pip install uvicorn[/red]")
        sys.exit(1)
    from secureaudit.dashboard.app import create_app
    console.print(f"[bold cyan]🔐 SecureAudit Dashboard[/bold cyan] → http://{host}:{port}")
    app = create_app(db)
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
              help="Webhook URL — only called on score regression.")
@click.option("--fail-below", default=70, show_default=True,
              help="Alert if score drops below this threshold.")
@click.option("--output-dir", default=None,
              help="Directory to write HTML reports per run.")
def schedule(target, cron, config, plugins, db, alert_webhook, fail_below, output_dir):
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
        fail_below=fail_below,
        output_dir=output_dir,
        config_path=config,
    )


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

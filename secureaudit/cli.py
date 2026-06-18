"""
SecureAudit CLI.
"""

from __future__ import annotations

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

_SEV_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


@click.group()
@click.version_option("1.0.0", prog_name="secureaudit")
def cli():
    """🔐 SecureAudit — multi-plugin security audit tool."""


@cli.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--config", "-c", default=None, help="Path to secureaudit.yml")
@click.option("--plugins", "-p", default=None, help="Comma-separated list of plugins to run")
@click.option("--output", "-o", default=None, help="Write HTML report to file")
@click.option("--json", "json_out", default=None, help="Write JSON report to file")
@click.option("--fail-below", default=None, type=int, help="Exit 1 if score below threshold")
@click.option("--no-terminal", is_flag=True, help="Suppress terminal output")
def scan(target, config, plugins, output, json_out, fail_below, no_terminal, sarif_out, db):
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

    # Score panel
    console.print(Panel(
        f"[{score_color}][bold]{score}/100[/bold][/{score_color}]  Grade [{score_color}]{grade}[/{score_color}]"
        f"  [{status_color}]{status}[/{status_color}]  "
        f"[dim](threshold: {threshold})[/dim]\n"
        f"[bold red]■[/bold red] {counts.get('CRITICAL',0)} Critical  "
        f"[red]■[/red] {counts.get('HIGH',0)} High  "
        f"[yellow]■[/yellow] {counts.get('MEDIUM',0)} Medium  "
        f"[blue]■[/blue] {counts.get('LOW',0)} Low  "
        f"[dim]■[/dim] {counts.get('INFO',0)} Info",
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


def main():
    cli()


if __name__ == "__main__":
    main()

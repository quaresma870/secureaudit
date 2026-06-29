"""
Terminal rendering for an AuditResult — shared by `scan` and `schedule`.

Extracted from a private, cli.py-only function after finding scheduler.py
imported this from a module path (`secureaudit.output.terminal`) that
doesn't exist anywhere in the codebase — the `schedule` command crashed
with ModuleNotFoundError on every single invocation, immediately, before
even getting to its first scheduled run. Giving this a real, importable
home fixes that import for good, rather than just patching the path to
point at cli.py's private function (the wrong direction for a CLI module
to be importing application logic from).
"""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from secureaudit.core.models import Severity

console = Console()

_SEV_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


def print_summary(result, threshold: int = 70) -> None:
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
        f"[bold red]■[/bold red] {counts.get('CRITICAL', 0)} Critical  "
        f"[red]■[/red] {counts.get('HIGH', 0)} High  "
        f"[yellow]■[/yellow] {counts.get('MEDIUM', 0)} Medium  "
        f"[blue]■[/blue] {counts.get('LOW', 0)} Low  "
        f"[dim]■[/dim] {counts.get('INFO', 0)} Info"
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

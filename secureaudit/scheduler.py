"""
Scheduler — runs security audits on a cron schedule.
Only alerts when score drops vs previous run (no noise on stable repos).
"""

from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path

from rich.console import Console

console = Console()


def _parse_cron(cron_expr: str, job_fn):
    try:
        import schedule
    except ImportError:
        raise RuntimeError("Install schedule: pip install schedule")

    parts = cron_expr.strip().split()
    if len(parts) != 5:
        raise ValueError(f"Need 5 cron fields, got: {cron_expr!r}")

    minute, hour, _dom, _month, _dow = parts

    if minute.startswith("*/") and hour == "*":
        return schedule.every(int(minute[2:])).minutes.do(job_fn)
    if hour.startswith("*/") and minute == "0":
        return schedule.every(int(hour[2:])).hours.do(job_fn)
    if minute.isdigit() and hour.isdigit():
        t = f"{int(hour):02d}:{int(minute):02d}"
        return schedule.every().day.at(t).do(job_fn)

    dow_map = {"0": "monday", "1": "tuesday", "2": "wednesday",
               "3": "thursday", "4": "friday", "5": "saturday", "6": "sunday"}
    if _dow in dow_map and minute.isdigit() and hour.isdigit():
        t = f"{int(hour):02d}:{int(minute):02d}"
        return getattr(schedule.every(), dow_map[_dow]).at(t).do(job_fn)

    raise ValueError(f"Unsupported cron: {cron_expr!r}")


def _send_alert(webhook_url: str, payload: dict) -> None:
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            webhook_url, data=data,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass


def run_schedule(
    target: str,
    cron_expr: str,
    plugins: list[str] | None,
    db: str | None,
    alert_webhook: str | None,
    fail_below: int,
    output_dir: str | None,
    config_path: str | None,
    alert_slack: str | None = None,
    alert_teams: str | None = None,
    dashboard_url: str | None = None,
) -> None:
    """Run security audits on a cron schedule."""
    try:
        import schedule
    except ImportError:
        console.print("[red]Install schedule: pip install schedule[/red]")
        return

    from secureaudit.core.config import load_config
    from secureaudit.core.engine import AuditEngine
    from secureaudit.output.terminal import print_summary

    cfg = load_config(config_path)
    engine = AuditEngine(cfg)

    run_count = [0]
    prev_score = [None]

    def job():
        run_count[0] += 1
        console.rule(f"[cyan]Audit run #{run_count[0]}[/cyan]")

        result = engine.run(target, plugins)
        print_summary(result)

        # Persist
        run_id = None
        if db:
            from secureaudit.reports.history import save
            run_id = save(result, db, project=cfg.project)
            console.print(f"[green]✔[/green] Saved to {db} (run #{run_id})")

            if cfg.project:
                from secureaudit.core.webhooks import check_and_fire_project_webhooks
                fired = check_and_fire_project_webhooks(db, cfg.project, run_id)
                if fired:
                    console.print(f"[yellow]🔔 {fired} webhook(s) notified — new regression detected[/yellow]")

        # HTML report
        if output_dir:
            from datetime import datetime

            from secureaudit.reports.html import write_html
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            out = Path(output_dir) / f"report_{ts}.html"
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            write_html(result, out)
            console.print(f"[green]✔[/green] HTML: {out}")

        # Alert only on regression vs previous run
        score = result.score
        should_alert = False
        reason = ""

        if score < fail_below:
            should_alert = True
            reason = f"Score {score} is below threshold {fail_below}"
        elif prev_score[0] is not None and score < prev_score[0]:
            should_alert = True
            reason = f"Score dropped from {prev_score[0]} to {score}"

        prev_score[0] = score

        if should_alert and alert_webhook:
            counts = result.counts_by_severity()
            _send_alert(alert_webhook, {
                "repo": target,
                "run": run_count[0],
                "score": score,
                "grade": result.grade,
                "reason": reason,
                "critical": counts.get("CRITICAL", 0),
                "high": counts.get("HIGH", 0),
                "run_url": f"run #{run_id}" if run_id else "N/A",
            })
            console.print(f"[yellow]⚠  Webhook alert sent:[/yellow] {reason}")

        if should_alert and alert_slack:
            from secureaudit.notifications import send_slack
            send_slack(alert_slack, result, dashboard_url)
            console.print(f"[yellow]⚠  Slack alert sent:[/yellow] {reason}")

        if should_alert and alert_teams:
            from secureaudit.notifications import send_teams
            send_teams(alert_teams, result, dashboard_url)
            console.print(f"[yellow]⚠  Teams alert sent:[/yellow] {reason}")

        if should_alert and not (alert_webhook or alert_slack or alert_teams):
            console.print(f"[yellow]⚠  {reason}[/yellow]")

    _parse_cron(cron_expr, job)
    console.print(
        f"[bold cyan]⏱  SecureAudit scheduled:[/bold cyan] "
        f"[green]{cron_expr}[/green] — Ctrl+C to stop\n"
    )
    job()  # run immediately on start

    try:
        while True:
            schedule.run_pending()
            time.sleep(30)
    except KeyboardInterrupt:
        console.print("\n[cyan]Scheduler stopped.[/cyan]")

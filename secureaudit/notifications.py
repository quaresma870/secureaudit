"""
Notifications — native Slack (Block Kit) and Microsoft Teams (Adaptive Cards)
templates, plus a weekly digest summary.

Generic webhooks send raw JSON, which renders as an unreadable blob in both
platforms. These builders produce payloads that actually display correctly.
"""

from __future__ import annotations

import json
import urllib.request

from secureaudit.core.models import AuditResult, Severity

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def score_color_hex(score: int) -> str:
    """Green ≥90, yellow 60-89, red <60."""
    if score >= 90:
        return "#22c55e"
    if score >= 60:
        return "#f59e0b"
    return "#ef4444"


def score_color_name(score: int) -> str:
    """Adaptive Card colour token equivalent of score_color_hex."""
    if score >= 90:
        return "good"
    if score >= 60:
        return "warning"
    return "attention"


def score_emoji(score: int) -> str:
    if score >= 90:
        return "🟢"
    if score >= 60:
        return "🟡"
    return "🔴"


def _top_findings(result: AuditResult, limit: int = 3) -> list[str]:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    findings = sorted(result.all_findings, key=lambda f: order.index(f.severity.value))
    lines = []
    for f in findings[:limit]:
        loc = ""
        if f.file:
            loc = f" — `{f.file}{':' + str(f.line) if f.line else ''}`"
        lines.append(f"{_SEVERITY_EMOJI[f.severity]} *{f.severity.value}* {f.plugin}: {f.title}{loc}")
    return lines


def _post_json(url: str, payload: dict, timeout: int = 5) -> bool:
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}, method="POST",
        )
        urllib.request.urlopen(req, timeout=timeout)
        return True
    except Exception:
        return False


# ── Slack (Block Kit) ─────────────────────────────────────────────────────────

def build_slack_payload(result: AuditResult, dashboard_url: str | None = None) -> dict:
    counts = result.counts_by_severity()
    score = result.score

    blocks: list[dict] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🔐 SecureAudit — {result.target}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Score:*\n{score_emoji(score)} {score}/100"},
                {"type": "mrkdwn", "text": f"*Grade:*\n{result.grade}"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"🔴 {counts.get('CRITICAL', 0)} Critical  "
                    f"🟠 {counts.get('HIGH', 0)} High  "
                    f"🟡 {counts.get('MEDIUM', 0)} Medium  "
                    f"🔵 {counts.get('LOW', 0)} Low"
                ),
            },
        },
    ]

    top = _top_findings(result)
    if top:
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Top findings:*\n" + "\n".join(top)},
        })

    if dashboard_url:
        blocks.append({
            "type": "actions",
            "elements": [{
                "type": "button",
                "text": {"type": "plain_text", "text": "View full report"},
                "url": dashboard_url,
            }],
        })

    return {"attachments": [{"color": score_color_hex(score), "blocks": blocks}]}


def send_slack(webhook_url: str, result: AuditResult, dashboard_url: str | None = None) -> bool:
    return _post_json(webhook_url, build_slack_payload(result, dashboard_url))


def build_slack_digest(runs: list[dict], target: str) -> dict:
    """Weekly digest from a list of history rows (newest first)."""
    if not runs:
        return {"text": f"🔐 SecureAudit weekly digest — {target}: no runs recorded this week."}

    latest = runs[0]
    oldest = runs[-1]
    delta = latest["score"] - oldest["score"]
    trend = "📈 improved" if delta > 0 else ("📉 regressed" if delta < 0 else "➡️ unchanged")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🔐 SecureAudit Weekly Digest — {target}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Latest score:*\n{score_emoji(latest['score'])} "
                                            f"{latest['score']}/100 (Grade {latest['grade']})"},
                {"type": "mrkdwn", "text": f"*7-day trend:*\n{trend} ({delta:+d} pts)"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Runs this week:* {len(runs)}\n"
                        f"*Latest critical+high findings:* {latest['critical_high']}",
            },
        },
    ]
    return {"attachments": [{"color": score_color_hex(latest["score"]), "blocks": blocks}]}


def send_slack_digest(webhook_url: str, runs: list[dict], target: str) -> bool:
    return _post_json(webhook_url, build_slack_digest(runs, target))


# ── Microsoft Teams (Adaptive Cards) ──────────────────────────────────────────

def build_teams_payload(result: AuditResult, dashboard_url: str | None = None) -> dict:
    counts = result.counts_by_severity()
    score = result.score

    body: list[dict] = [
        {
            "type": "TextBlock",
            "text": f"🔐 SecureAudit — {result.target}",
            "weight": "Bolder",
            "size": "Medium",
            "wrap": True,
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column", "width": "auto",
                    "items": [
                        {"type": "TextBlock", "text": "Score", "isSubtle": True},
                        {"type": "TextBlock", "text": f"{score}/100", "size": "ExtraLarge",
                         "weight": "Bolder", "color": score_color_name(score)},
                    ],
                },
                {
                    "type": "Column", "width": "auto",
                    "items": [
                        {"type": "TextBlock", "text": "Grade", "isSubtle": True},
                        {"type": "TextBlock", "text": result.grade, "size": "ExtraLarge",
                         "weight": "Bolder", "color": score_color_name(score)},
                    ],
                },
            ],
        },
        {
            "type": "TextBlock",
            "text": (
                f"🔴 {counts.get('CRITICAL', 0)} Critical  "
                f"🟠 {counts.get('HIGH', 0)} High  "
                f"🟡 {counts.get('MEDIUM', 0)} Medium  "
                f"🔵 {counts.get('LOW', 0)} Low"
            ),
            "wrap": True,
            "spacing": "Medium",
        },
    ]

    top = _top_findings(result)
    if top:
        body.append({
            "type": "TextBlock", "text": "Top findings:", "weight": "Bolder", "spacing": "Medium",
        })
        body.append({
            "type": "TextBlock",
            "text": "\n".join(f"- {line}" for line in top),
            "wrap": True,
        })

    card: dict = {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.4",
        "body": body,
    }

    if dashboard_url:
        card["actions"] = [{"type": "Action.OpenUrl", "title": "View full report", "url": dashboard_url}]

    return {
        "type": "message",
        "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}],
    }


def send_teams(webhook_url: str, result: AuditResult, dashboard_url: str | None = None) -> bool:
    return _post_json(webhook_url, build_teams_payload(result, dashboard_url))

"""
Project webhooks — notify external systems (ticketing, ChatOps, anything
that accepts a POST) when a project's new run introduces new CRITICAL/HIGH
findings versus its previous run for that project.

Registered via the dashboard API: POST /api/projects/{name}/webhooks
"""

from __future__ import annotations

import json
import sqlite3
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS project_webhooks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    project    TEXT NOT NULL,
    url        TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA)


def register_webhook(db_path: str | Path, project: str, url: str) -> int:
    conn = sqlite3.connect(str(db_path))
    _ensure_schema(conn)
    cur = conn.execute(
        "INSERT INTO project_webhooks (project, url, created_at) VALUES (?,?,?)",
        (project, url, datetime.now(UTC).isoformat()),
    )
    conn.commit()
    webhook_id = cur.lastrowid
    conn.close()
    return webhook_id


def get_webhooks(db_path: str | Path, project: str) -> list[dict]:
    conn = sqlite3.connect(str(db_path))
    _ensure_schema(conn)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM project_webhooks WHERE project = ? ORDER BY id", (project,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_webhook(db_path: str | Path, webhook_id: int) -> bool:
    conn = sqlite3.connect(str(db_path))
    _ensure_schema(conn)
    cur = conn.execute("DELETE FROM project_webhooks WHERE id = ?", (webhook_id,))
    conn.commit()
    deleted = cur.rowcount > 0
    conn.close()
    return deleted


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


def check_and_fire_project_webhooks(db_path: str | Path, project: str, run_id: int) -> int:
    """Compare `run_id` against the previous run for `project`; fire every
    registered webhook for that project if new CRITICAL/HIGH findings were
    introduced. Returns the number of webhooks actually fired (0 if no
    registered webhooks, no previous run to diff against, or no regression).
    """
    webhooks = get_webhooks(db_path, project)
    if not webhooks:
        return 0

    from secureaudit.reports.history import get_previous_run

    previous = get_previous_run(db_path, project, before_run_id=run_id)
    if previous is None:
        return 0  # first run for this project — nothing to diff against yet

    from secureaudit.core.diff import diff_runs

    diff = diff_runs(db_path, previous["id"], run_id)
    if not diff.has_new_regression:
        return 0

    payload = {
        "project": project,
        "run_id": run_id,
        "previous_run_id": previous["id"],
        "new_findings_count": len(diff.new),
        "new_findings": diff.new,
    }

    fired = 0
    for hook in webhooks:
        if _post_json(hook["url"], payload):
            fired += 1
    return fired

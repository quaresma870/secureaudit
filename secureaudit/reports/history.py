"""
SQLite history — persist audit results for score trending.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from secureaudit.core.models import AuditResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT    NOT NULL,
    timestamp   TEXT    NOT NULL,
    score       INTEGER NOT NULL,
    grade       TEXT    NOT NULL,
    total       INTEGER NOT NULL,
    errors      INTEGER NOT NULL,
    warnings    INTEGER NOT NULL,
    error_rate  REAL    NOT NULL,
    duration_ms REAL    NOT NULL,
    sources     TEXT    NOT NULL,
    plugins     TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL,
    plugin      TEXT    NOT NULL,
    title       TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    file        TEXT,
    line        INTEGER,
    description TEXT,
    remediation TEXT,
    FOREIGN KEY (run_id) REFERENCES runs(id)
);
"""


def save(result: AuditResult, db_path: str | Path) -> int:
    """Persist an AuditResult to SQLite. Returns the run ID."""
    conn = sqlite3.connect(str(db_path))
    conn.executescript(_SCHEMA)

    counts = result.counts_by_severity()
    cur = conn.execute(
        """INSERT INTO runs
           (target, timestamp, score, grade, total, errors, warnings,
            error_rate, duration_ms, sources, plugins)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (
            result.target,
            result.timestamp.isoformat(),
            result.score,
            result.grade,
            result.total,
            counts.get("CRITICAL", 0) + counts.get("HIGH", 0),
            counts.get("WARNING", 0),
            result.error_rate if hasattr(result, "error_rate") else 0.0,
            result.duration_ms,
            json.dumps(result.sources),
            json.dumps([pr.plugin for pr in result.plugin_results]),
        ),
    )
    run_id = cur.lastrowid

    for f in result.all_findings:
        conn.execute(
            """INSERT INTO findings
               (run_id, plugin, title, severity, file, line, description, remediation)
               VALUES (?,?,?,?,?,?,?,?)""",
            (run_id, f.plugin, f.title, f.severity.value,
             f.file, f.line, f.description, f.remediation),
        )

    conn.commit()
    conn.close()
    return run_id


def get_runs(db_path: str | Path, limit: int = 20) -> list[dict]:
    """Return recent runs ordered by newest first."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_run_findings(db_path: str | Path, run_id: int) -> list[dict]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM findings WHERE run_id = ?", (run_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

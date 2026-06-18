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
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    target           TEXT    NOT NULL,
    timestamp        TEXT    NOT NULL,
    score            INTEGER NOT NULL,
    grade            TEXT    NOT NULL,
    total_findings   INTEGER NOT NULL,
    critical_high    INTEGER NOT NULL,
    suppressed_count INTEGER NOT NULL DEFAULT 0,
    duration_ms      REAL    NOT NULL,
    plugins          TEXT    NOT NULL
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
    suppressed  INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (run_id) REFERENCES runs(id)
);
"""


def save(result: AuditResult, db_path: str | Path) -> int:
    """Persist an AuditResult to SQLite. Returns the run ID."""
    conn = sqlite3.connect(str(db_path))
    conn.executescript(_SCHEMA)

    counts = result.counts_by_severity()
    all_findings = result.all_findings

    cur = conn.execute(
        """INSERT INTO runs
           (target, timestamp, score, grade, total_findings, critical_high,
            suppressed_count, duration_ms, plugins)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (
            result.target,
            result.timestamp.isoformat(),
            result.score,
            result.grade,
            len(all_findings),
            counts.get("CRITICAL", 0) + counts.get("HIGH", 0),
            len(result.suppressed_findings),
            result.duration_ms,
            json.dumps([pr.plugin for pr in result.plugin_results]),
        ),
    )
    run_id = cur.lastrowid

    for f in all_findings:
        conn.execute(
            """INSERT INTO findings
               (run_id, plugin, title, severity, file, line, description, remediation, suppressed)
               VALUES (?,?,?,?,?,?,?,?,0)""",
            (run_id, f.plugin, f.title, f.severity.value,
             f.file, f.line, f.description, f.remediation),
        )

    for f in result.suppressed_findings:
        conn.execute(
            """INSERT INTO findings
               (run_id, plugin, title, severity, file, line, description, remediation, suppressed)
               VALUES (?,?,?,?,?,?,?,?,1)""",
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


def get_run_findings(db_path: str | Path, run_id: int, include_suppressed: bool = False) -> list[dict]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    if include_suppressed:
        rows = conn.execute(
            "SELECT * FROM findings WHERE run_id = ?", (run_id,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM findings WHERE run_id = ? AND suppressed = 0", (run_id,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

"""
SQLite history — persist audit results for score trending, optionally
grouped under a named project so multiple repos/targets can be viewed
together (see secureaudit.yml's `project:` key).
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
    project          TEXT,
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


def _ensure_schema(conn: sqlite3.Connection) -> None:
    """Create tables if absent, and migrate older databases that predate
    the `project` column — fully backward compatible with existing audits.db files."""
    conn.executescript(_SCHEMA)
    cols = [row[1] for row in conn.execute("PRAGMA table_info(runs)").fetchall()]
    if "project" not in cols:
        conn.execute("ALTER TABLE runs ADD COLUMN project TEXT")


def save(result: AuditResult, db_path: str | Path, project: str | None = None) -> int:
    """Persist an AuditResult to SQLite. Returns the run ID.

    `project` is optional — omitting it (or passing None) keeps the run
    ungrouped, exactly as before this feature existed.
    """
    conn = sqlite3.connect(str(db_path))
    _ensure_schema(conn)

    counts = result.counts_by_severity()
    all_findings = result.all_findings

    cur = conn.execute(
        """INSERT INTO runs
           (target, project, timestamp, score, grade, total_findings, critical_high,
            suppressed_count, duration_ms, plugins)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (
            result.target,
            project,
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


def get_runs(db_path: str | Path, limit: int = 20, project: str | None = None) -> list[dict]:
    """Return recent runs ordered by newest first. Optionally filtered to a single project."""
    conn = sqlite3.connect(str(db_path))
    _ensure_schema(conn)
    conn.row_factory = sqlite3.Row
    if project is not None:
        rows = conn.execute(
            "SELECT * FROM runs WHERE project = ? ORDER BY id DESC LIMIT ?", (project, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_run_findings(db_path: str | Path, run_id: int, include_suppressed: bool = False) -> list[dict]:
    conn = sqlite3.connect(str(db_path))
    _ensure_schema(conn)
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


def get_projects(db_path: str | Path) -> list[dict]:
    """Return one row per named project — its latest run — for a portfolio-style overview.

    Runs with no project set (project IS NULL) are intentionally excluded:
    they remain visible via get_runs() without a project filter, same as
    before this feature existed.
    """
    conn = sqlite3.connect(str(db_path))
    _ensure_schema(conn)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT r.* FROM runs r
        INNER JOIN (
            SELECT project, MAX(id) AS max_id
            FROM runs
            WHERE project IS NOT NULL
            GROUP BY project
        ) latest
        ON r.project = latest.project AND r.id = latest.max_id
        ORDER BY r.project
        """
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_project_run_count(db_path: str | Path, project: str) -> int:
    conn = sqlite3.connect(str(db_path))
    _ensure_schema(conn)
    count = conn.execute(
        "SELECT COUNT(*) FROM runs WHERE project = ?", (project,)
    ).fetchone()[0]
    conn.close()
    return count

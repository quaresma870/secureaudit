"""
Diff — compare findings between two persisted scan runs.

Score deltas alone don't tell a reviewer *which* vulnerability was introduced
or fixed. This module matches findings across runs by a stable key
(plugin + rule slug + file) so that line-number drift between runs doesn't
cause false new/resolved pairs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from secureaudit.reports.history import get_run_findings, get_runs

_REGRESSION_SEVERITIES = ("CRITICAL", "HIGH")


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "unknown-rule"


def _row_key(row: dict) -> str:
    """Stable key for a finding row, mirroring Finding.fingerprint()'s approach."""
    return f"{row['plugin']}:{_slugify(row['title'])}:{row.get('file') or ''}"


def resolve_run_id(db_path: str, ref: str) -> int:
    """Resolve a run reference — a numeric ID, or the keywords 'latest'/'previous'."""
    if ref.isdigit():
        return int(ref)

    if ref == "latest":
        runs = get_runs(db_path, limit=1)
        if not runs:
            raise ValueError("No runs found in database.")
        return runs[0]["id"]

    if ref == "previous":
        runs = get_runs(db_path, limit=2)
        if len(runs) < 2:
            raise ValueError("Not enough runs to resolve 'previous' (need at least 2).")
        return runs[1]["id"]

    raise ValueError(f"Invalid run reference: {ref!r}. Use a run ID, 'latest', or 'previous'.")


@dataclass
class DiffResult:
    run1_id: int
    run2_id: int
    new: list[dict] = field(default_factory=list)
    resolved: list[dict] = field(default_factory=list)
    unchanged_count: int = 0

    @property
    def has_new_regression(self) -> bool:
        """True if any newly introduced finding is CRITICAL or HIGH severity."""
        return any(f["severity"] in _REGRESSION_SEVERITIES for f in self.new)

    def to_dict(self) -> dict:
        return {
            "run1": self.run1_id,
            "run2": self.run2_id,
            "new": self.new,
            "resolved": self.resolved,
            "unchanged_count": self.unchanged_count,
            "regression": self.has_new_regression,
        }


def diff_runs(
    db_path: str, run1_id: int, run2_id: int, include_suppressed: bool = False
) -> DiffResult:
    """Compare findings from run1 to run2. run1 is the baseline ('before'),
    run2 is what changed since ('after')."""
    findings1 = get_run_findings(db_path, run1_id, include_suppressed=include_suppressed)
    findings2 = get_run_findings(db_path, run2_id, include_suppressed=include_suppressed)

    keys1 = {_row_key(f): f for f in findings1}
    keys2 = {_row_key(f): f for f in findings2}

    new_keys = set(keys2) - set(keys1)
    resolved_keys = set(keys1) - set(keys2)
    unchanged_keys = set(keys1) & set(keys2)

    result = DiffResult(run1_id=run1_id, run2_id=run2_id)
    result.new = [keys2[k] for k in new_keys]
    result.resolved = [keys1[k] for k in resolved_keys]
    result.unchanged_count = len(unchanged_keys)
    return result

"""
JSON report serialiser.
"""

from __future__ import annotations

import json
from pathlib import Path

from secureaudit.core.models import AuditResult


def write_json(result: AuditResult, path: str | Path) -> None:
    data = result.to_dict()
    Path(path).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

"""
Baseline and suppressions — accept existing findings as known/expected,
and support inline `# secureaudit-ignore` comments.

Without this, every finding reappears on every scan forever, turning the
tool into noise. Baseline + inline suppression let teams acknowledge
accepted risk while keeping suppressed findings visible (not silently
dropped) for auditability.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

from secureaudit.core.models import AuditResult, Finding

_BASELINE_VERSION = 1
_DEFAULT_BASELINE_NAME = ".secureaudit-baseline.json"

_IGNORE_RE = re.compile(
    r"secureaudit-ignore"
    r"(?::\s*([a-z0-9\-]+))?"           # optional rule slug
    r'(?:\s+reason="([^"]*)")?'          # optional reason="..."
    r"(?:\s+until=(\d{4}-\d{2}-\d{2}))?",  # optional until=YYYY-MM-DD
    re.IGNORECASE,
)


def default_baseline_path(target: str | Path) -> Path:
    return Path(target) / _DEFAULT_BASELINE_NAME


# ── Baseline file ─────────────────────────────────────────────────────────────

def load_baseline(path: str | Path) -> dict | None:
    path = Path(path)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def save_baseline(
    path: str | Path,
    findings: list[Finding],
    target: str,
    merge: bool = True,
) -> int:
    """Write a baseline file accepting the given findings. Returns total count."""
    path = Path(path)
    existing = load_baseline(path) if merge else None
    fingerprints: dict[str, dict] = existing["fingerprints"] if existing else {}

    now = datetime.now(UTC).isoformat()
    for f in findings:
        fp = f.fingerprint()
        if fp not in fingerprints:
            fingerprints[fp] = {
                "plugin": f.plugin,
                "rule": f.rule_slug,
                "title": f.title,
                "file": f.file,
                "accepted_at": now,
            }

    data = {
        "version": _BASELINE_VERSION,
        "created": existing["created"] if existing else now,
        "updated": now,
        "target": target,
        "fingerprints": fingerprints,
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return len(fingerprints)


# ── Inline suppressions ──────────────────────────────────────────────────────

@dataclass
class SuppressionRule:
    rule_slug: str | None
    reason: str | None
    until: date | None

    def matches(self, finding: Finding) -> bool:
        if self.rule_slug and self.rule_slug != finding.rule_slug:
            return False
        return True

    def is_expired(self) -> bool:
        if self.until is None:
            return False
        return date.today() > self.until


def scan_inline_suppressions(
    target: Path,
    exclude_paths: set[str],
    max_file_size_kb: int = 1024,
) -> dict[tuple[str, int], SuppressionRule]:
    """Scan all text files under target for `# secureaudit-ignore` comments."""
    result: dict[tuple[str, int], SuppressionRule] = {}
    max_size = max_file_size_kb * 1024

    for f in target.rglob("*"):
        if not f.is_file():
            continue
        if any(part in exclude_paths for part in f.parts):
            continue
        try:
            if f.stat().st_size > max_size:
                continue
            content = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        rel = str(f.relative_to(target))
        for line_num, line in enumerate(content.splitlines(), 1):
            if "secureaudit-ignore" not in line.lower():
                continue
            m = _IGNORE_RE.search(line)
            if not m:
                continue
            rule_slug, reason, until_str = m.groups()
            until = date.fromisoformat(until_str) if until_str else None
            result[(rel, line_num)] = SuppressionRule(
                rule_slug=rule_slug, reason=reason, until=until
            )

    return result


# ── Apply suppressions to a result ──────────────────────────────────────────

def apply_suppressions(
    result: AuditResult,
    target: Path,
    baseline_path: Path | None = None,
    exclude_paths: set[str] | None = None,
    check_inline: bool = True,
) -> AuditResult:
    """Move baselined/inline-suppressed findings out of active plugin results
    and into result.suppressed_findings. Mutates and returns `result`.
    """
    baseline = load_baseline(baseline_path) if baseline_path else None
    baseline_fps: set[str] = set(baseline["fingerprints"].keys()) if baseline else set()

    inline_map: dict[tuple[str, int], SuppressionRule] = {}
    if check_inline:
        inline_map = scan_inline_suppressions(target, exclude_paths or set())

    for pr in result.plugin_results:
        active: list[Finding] = []
        for finding in pr.findings:
            reason = _suppression_reason(finding, baseline_fps, inline_map)
            if reason:
                finding.suppressed_reason = reason
                result.suppressed_findings.append(finding)
            else:
                active.append(finding)
        pr.findings = active

    return result


def _suppression_reason(
    finding: Finding,
    baseline_fps: set[str],
    inline_map: dict[tuple[str, int], SuppressionRule],
) -> str | None:
    if finding.fingerprint() in baseline_fps:
        return "baseline"

    if finding.file and finding.line:
        rule = inline_map.get((finding.file, finding.line))
        if rule and rule.matches(finding) and not rule.is_expired():
            return f"inline: {rule.reason}" if rule.reason else "inline"

    return None

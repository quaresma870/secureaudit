"""
Core data models — shared across all plugins and reports.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def score_penalty(self) -> int:
        return {
            self.CRITICAL: 25,
            self.HIGH: 15,
            self.MEDIUM: 7,
            self.LOW: 3,
            self.INFO: 0,
        }[self]

    @property
    def color(self) -> str:
        return {
            self.CRITICAL: "#ef4444",
            self.HIGH: "#f97316",
            self.MEDIUM: "#f59e0b",
            self.LOW: "#3b82f6",
            self.INFO: "#6b7280",
        }[self]


@dataclass
class Finding:
    """A single security finding from a plugin."""

    plugin: str
    title: str
    severity: Severity
    description: str
    file: str | None = None
    line: int | None = None
    evidence: str | None = None
    remediation: str | None = None
    reference: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    suppressed_reason: str | None = None

    @property
    def rule_slug(self) -> str:
        """Stable, human-readable identifier for this finding's rule.

        Prefers an explicit rule id from plugin metadata (e.g. Semgrep check_id,
        Trivy check ID) and falls back to a slugified title.
        """
        base = self.extra.get("rule_id") or self.extra.get("check_id") or self.title
        slug = re.sub(r"[^a-z0-9]+", "-", str(base).lower()).strip("-")
        return slug or "unknown-rule"

    def fingerprint(self) -> str:
        """Stable fingerprint independent of line number drift.

        Used by baseline/suppression matching so that findings survive
        minor file edits that shift line numbers without changing the issue.
        """
        key = f"{self.plugin}:{self.rule_slug}:{self.file or ''}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "plugin": self.plugin,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "reference": self.reference,
            "extra": self.extra,
            "fingerprint": self.fingerprint(),
            "suppressed_reason": self.suppressed_reason,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Finding:
        """Reconstruct a Finding from a to_dict()-style mapping.

        Used by the incremental scan cache to deserialise previously stored
        results. Ignores computed-only keys (fingerprint) since those are
        derived, not stored state.
        """
        return cls(
            plugin=data["plugin"],
            title=data["title"],
            severity=Severity(data["severity"]),
            description=data.get("description", ""),
            file=data.get("file"),
            line=data.get("line"),
            evidence=data.get("evidence"),
            remediation=data.get("remediation"),
            reference=data.get("reference"),
            extra=data.get("extra") or {},
            suppressed_reason=data.get("suppressed_reason"),
        )


@dataclass
class PluginResult:
    """Result from a single plugin run."""

    plugin: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    duration_ms: float = 0.0

    @property
    def passed(self) -> bool:
        return self.error is None and not any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings
        )

    @property
    def score(self) -> int:
        penalty = sum(f.severity.score_penalty for f in self.findings)
        return max(0, 100 - penalty)

    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)


@dataclass
class AuditResult:
    """Aggregated result of a full audit run."""

    target: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    plugin_results: list[PluginResult] = field(default_factory=list)
    duration_ms: float = 0.0
    suppressed_findings: list[Finding] = field(default_factory=list)

    @property
    def all_findings(self) -> list[Finding]:
        findings = []
        for pr in self.plugin_results:
            findings.extend(pr.findings)
        return findings

    @property
    def score(self) -> int:
        """Global security score 0–100."""
        if not self.plugin_results:
            return 100
        penalty = sum(f.severity.score_penalty for f in self.all_findings)
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 90:
            return "A"
        if s >= 75:
            return "B"
        if s >= 60:
            return "C"
        if s >= 40:
            return "D"
        return "F"

    def counts_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.all_findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "timestamp": self.timestamp.isoformat(),
            "score": self.score,
            "grade": self.grade,
            "duration_ms": self.duration_ms,
            "severity_counts": self.counts_by_severity(),
            "suppressed_count": len(self.suppressed_findings),
            "suppressed": [f.to_dict() for f in self.suppressed_findings],
            "plugins": [
                {
                    "plugin": pr.plugin,
                    "score": pr.score,
                    "passed": pr.passed,
                    "duration_ms": pr.duration_ms,
                    "error": pr.error,
                    "findings": [f.to_dict() for f in pr.findings],
                }
                for pr in self.plugin_results
            ],
        }

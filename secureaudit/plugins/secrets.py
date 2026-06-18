"""
Secrets plugin — detects exposed secrets, API keys, tokens and passwords in code.
Uses regex patterns + Shannon entropy to reduce false positives.
"""

from __future__ import annotations

import math
import re
from pathlib import Path

from secureaudit.core.models import Finding, PluginResult, Severity
from secureaudit.plugins import BasePlugin, register

# Patterns: (name, regex, severity, remediation, check_entropy)
# check_entropy=False for specific/deterministic patterns that are always findings
_PATTERNS: list[tuple[str, re.Pattern, Severity, str, bool]] = [
    (
        "AWS Access Key",
        re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
        Severity.CRITICAL,
        "Rotate the key immediately via AWS IAM console.",
        False,  # specific prefix — always a finding
    ),
    (
        "AWS Secret Key",
        re.compile(r"aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})", re.I),
        Severity.CRITICAL,
        "Rotate the AWS secret key and remove from code.",
        True,
    ),
    (
        "GitHub Token",
        re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
        Severity.CRITICAL,
        "Revoke the token at github.com/settings/tokens.",
        True,
    ),
    (
        "Generic API Key",
        re.compile(r"(?:api[_\-\.]?key|apikey|api[_\-\.]?secret)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?", re.I),
        Severity.HIGH,
        "Move secrets to environment variables or a secrets manager.",
        True,
    ),
    (
        "Hardcoded Password",
        re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", re.I),
        Severity.HIGH,
        "Use environment variables or a secrets manager instead of hardcoded passwords.",
        True,
    ),
    (
        "Private Key Header",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        Severity.CRITICAL,
        "Never commit private keys. Add *.pem, *.key to .gitignore.",
        False,  # specific string — always a finding
    ),
    (
        "Database Connection String",
        re.compile(r"(?:postgresql|mysql|mongodb|redis)://[^:]+:[^@\s]{4,}@", re.I),
        Severity.HIGH,
        "Move database credentials to environment variables.",
        True,
    ),
    (
        "Slack Webhook",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
        Severity.HIGH,
        "Revoke the webhook at api.slack.com/apps.",
        False,  # specific URL pattern
    ),
    (
        "Generic Secret",
        re.compile(r"(?:secret|token)[_\-]?[=:]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]", re.I),
        Severity.MEDIUM,
        "Review and move to environment variables if this is a real secret.",
        True,
    ),
]

_ENTROPY_THRESHOLD = 4.0  # bits — filter low-entropy false positives


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


@register
class SecretsPlugin(BasePlugin):
    name = "secrets"
    description = "Detect exposed API keys, tokens, passwords and private keys"

    def audit(self, target: str | Path) -> PluginResult:
        target = Path(target)
        result = PluginResult(plugin=self.name)

        cfg = self.plugin_config
        exclude_exts = set(cfg.get("exclude_extensions", []))
        max_size = cfg.get("max_file_size_kb", 512) * 1024
        exclude_paths = set(self.config.exclude_paths)

        files = self._collect_files(target, exclude_paths, exclude_exts, max_size)

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            for line_num, line in enumerate(content.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith(("#", "//", "*", "<!--")):
                    continue

                for name, pattern, severity, remediation, check_entropy in _PATTERNS:
                    for match in pattern.finditer(line):
                        secret_val = match.group(1) if match.lastindex else match.group(0)
                        # Apply entropy filter only for generic patterns
                        if check_entropy and _shannon_entropy(secret_val) < _ENTROPY_THRESHOLD and len(secret_val) < 32:
                            continue
                        result.findings.append(Finding(
                            plugin=self.name,
                            title=f"{name} detected",
                            severity=severity,
                            description=f"Possible {name} found in {file_path.relative_to(target)}",
                            file=str(file_path.relative_to(target)),
                            line=line_num,
                            evidence=line.strip()[:120],
                            remediation=remediation,
                            reference="https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials",
                        ))

        return result

    def _collect_files(
        self, target: Path, exclude_paths: set, exclude_exts: set, max_size: int
    ) -> list[Path]:
        files = []
        for f in target.rglob("*"):
            if not f.is_file():
                continue
            if any(part in exclude_paths for part in f.parts):
                continue
            if f.suffix.lower() in exclude_exts:
                continue
            try:
                if f.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            files.append(f)
        return files

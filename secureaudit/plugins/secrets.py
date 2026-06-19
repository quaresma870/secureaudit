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

        if self.cache is not None:
            from secureaudit.core.cache import scan_with_cache
            result.findings = scan_with_cache(
                self, files, lambda f: self._scan_one_file(f, target),
            )
        else:
            result.findings = self.scan_files(files, target)

        return result

    def scan_files(self, files: list[Path], base: Path) -> list[Finding]:
        """Scan an explicit list of files for secrets.

        Public so callers like the pre-commit hook can scan only staged
        files without paying the cost of a full repository walk.
        """
        findings: list[Finding] = []
        for file_path in files:
            findings.extend(self._scan_one_file(file_path, base))
        return findings

    def _scan_one_file(self, file_path: Path, base: Path) -> list[Finding]:
        """Scan a single file. Split out from scan_files() so the incremental
        cache can key results per file rather than per batch."""
        findings: list[Finding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return findings

        try:
            rel_path = str(file_path.relative_to(base))
        except ValueError:
            rel_path = str(file_path)

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
                    findings.append(Finding(
                        plugin=self.name,
                        title=f"{name} detected",
                        severity=severity,
                        description=f"Possible {name} found in {rel_path}",
                        file=rel_path,
                        line=line_num,
                        evidence=line.strip()[:120],
                        remediation=remediation,
                        reference="https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials",
                    ))

        return findings

    def _collect_files(
        self, target: Path, exclude_paths: set, exclude_exts: set, max_size: int
    ) -> list[Path]:
        from secureaudit.core.cache import CACHE_DIR_NAME

        files = []
        for f in target.rglob("*"):
            if not f.is_file():
                continue
            if CACHE_DIR_NAME in f.parts:
                continue  # never scan our own cache, regardless of user exclude_paths config
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

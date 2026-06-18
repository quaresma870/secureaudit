"""
Filesystem plugin — checks file permissions, SUID/SGID bits, world-writable files,
and sensitive files that shouldn't be committed.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from secureaudit.core.models import Finding, PluginResult, Severity
from secureaudit.plugins import BasePlugin, register

# Sensitive files that should not be in a repo
_SENSITIVE_FILES = [
    (".env", Severity.HIGH, "Environment file with secrets"),
    (".env.local", Severity.HIGH, "Local environment file with secrets"),
    (".env.production", Severity.CRITICAL, "Production environment file"),
    ("id_rsa", Severity.CRITICAL, "Private SSH key"),
    ("id_ed25519", Severity.CRITICAL, "Private SSH key"),
    ("*.pem", Severity.CRITICAL, "PEM certificate/key file"),
    ("*.key", Severity.HIGH, "Key file"),
    ("*.p12", Severity.HIGH, "PKCS12 keystore"),
    ("*.pfx", Severity.HIGH, "PKCS12 keystore"),
    ("secrets.yml", Severity.HIGH, "Secrets file"),
    ("secrets.yaml", Severity.HIGH, "Secrets file"),
    ("credentials.json", Severity.HIGH, "Credentials file"),
    ("service-account.json", Severity.CRITICAL, "GCP service account key"),
    (".htpasswd", Severity.HIGH, "HTTP auth passwords"),
    ("wp-config.php", Severity.HIGH, "WordPress config with DB credentials"),
    ("database.yml", Severity.MEDIUM, "Database config"),
    ("config/database.yml", Severity.MEDIUM, "Rails database config"),
    (".npmrc", Severity.MEDIUM, "NPM config may contain auth tokens"),
    (".pypirc", Severity.MEDIUM, "PyPI config may contain API tokens"),
    ("terraform.tfvars", Severity.HIGH, "Terraform variables with secrets"),
    ("*.tfstate", Severity.HIGH, "Terraform state may contain secrets"),
]


@register
class FilesystemPlugin(BasePlugin):
    name = "filesystem"
    description = "Check file permissions, SUID bits, and sensitive committed files"

    def audit(self, target: str | Path) -> PluginResult:
        target = Path(target)
        result = PluginResult(plugin=self.name)
        exclude_paths = set(self.config.exclude_paths)

        # Check for sensitive files in repo
        result.findings.extend(self._check_sensitive_files(target, exclude_paths))

        # Check file permissions (only on Unix)
        if os.name == "posix":
            result.findings.extend(self._check_permissions(target, exclude_paths))

        if not result.findings:
            result.findings.append(Finding(
                plugin=self.name,
                title="No filesystem issues found",
                severity=Severity.INFO,
                description="No sensitive files or dangerous permissions detected.",
            ))

        return result

    def _check_sensitive_files(self, target: Path, exclude_paths: set) -> list[Finding]:
        findings = []
        for path in target.rglob("*"):
            if not path.is_file():
                continue
            if any(part in exclude_paths for part in path.parts):
                continue

            for pattern, severity, description in _SENSITIVE_FILES:
                if pattern.startswith("*"):
                    match = path.suffix == pattern[1:] or path.name.endswith(pattern[1:])
                else:
                    match = path.name == pattern or str(path.relative_to(target)) == pattern

                if match:
                    # Check if it's gitignored (best effort)
                    gitignore = target / ".gitignore"
                    if gitignore.exists():
                        gitignore_content = gitignore.read_text(errors="ignore")
                        if path.name in gitignore_content or pattern in gitignore_content:
                            # File is gitignored — lower severity
                            severity = Severity.INFO

                    findings.append(Finding(
                        plugin=self.name,
                        title=f"Sensitive file: {path.name}",
                        severity=severity,
                        description=description,
                        file=str(path.relative_to(target)),
                        remediation=f"Add '{path.name}' to .gitignore and remove from repository history.",
                        reference="https://owasp.org/www-community/vulnerabilities/Sensitive_Data_Exposure",
                    ))
                    break  # Only report once per file

        return findings

    def _check_permissions(self, target: Path, exclude_paths: set) -> list[Finding]:
        findings = []
        for path in target.rglob("*"):
            if any(part in exclude_paths for part in path.parts):
                continue
            try:
                mode = path.stat().st_mode
            except OSError:
                continue

            # World-writable files (not directories)
            if path.is_file() and bool(mode & stat.S_IWOTH):
                findings.append(Finding(
                    plugin=self.name,
                    title=f"World-writable file: {path.relative_to(target)}",
                    severity=Severity.MEDIUM,
                    description="File is writable by any user on the system.",
                    file=str(path.relative_to(target)),
                    evidence=f"Permissions: {oct(mode)[-3:]}",
                    remediation="Run: chmod o-w " + str(path.relative_to(target)),
                ))

            # SUID/SGID bit on files
            if path.is_file() and (bool(mode & stat.S_ISUID) or bool(mode & stat.S_ISGID)):
                bit = "SUID" if bool(mode & stat.S_ISUID) else "SGID"
                findings.append(Finding(
                    plugin=self.name,
                    title=f"{bit} bit set: {path.relative_to(target)}",
                    severity=Severity.HIGH,
                    description=f"The {bit} bit allows the file to run with elevated privileges.",
                    file=str(path.relative_to(target)),
                    evidence=f"Permissions: {oct(mode)[-4:]}",
                    remediation=f"Run: chmod u-s {path.relative_to(target)} (if SUID not required)",
                ))

        return findings

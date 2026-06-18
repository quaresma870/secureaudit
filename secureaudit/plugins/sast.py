"""
SAST plugin — static application security testing via Semgrep.

Detects code-level vulnerability patterns: SQL injection, command injection,
path traversal, SSRF, insecure deserialization, hardcoded crypto, etc.

Runs entirely locally — no code is sent to any cloud service.
Gracefully degrades to an INFO finding if the `semgrep` binary is not installed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from secureaudit.core.models import Finding, PluginResult, Severity
from secureaudit.plugins import BasePlugin, register

_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

# Some rule-id substrings warrant escalation regardless of Semgrep's own severity
_CRITICAL_HINTS = (
    "sql-injection", "sqli", "command-injection", "code-injection",
    "rce", "deserialization", "ssrf", "path-traversal", "hardcoded-secret",
)


@register
class SASTPlugin(BasePlugin):
    name = "sast"
    description = "Static code analysis for vulnerability patterns via Semgrep"

    def audit(self, target: str | Path) -> PluginResult:
        target = Path(target)
        result = PluginResult(plugin=self.name)

        semgrep_bin = shutil.which("semgrep")
        if not semgrep_bin:
            result.findings.append(Finding(
                plugin=self.name,
                title="Semgrep not installed — SAST check skipped",
                severity=Severity.INFO,
                description=(
                    "Semgrep is required for static code analysis but was not found on PATH."
                ),
                remediation=(
                    "Install Semgrep: pip install semgrep  (or: brew install semgrep)\n"
                    "See https://semgrep.dev/docs/getting-started/"
                ),
                reference="https://semgrep.dev/docs/getting-started/",
            ))
            return result

        cfg = self.plugin_config
        ruleset = cfg.get("config", "auto")
        timeout = cfg.get("timeout", 120)
        exclude_paths = self.config.exclude_paths

        cmd = [
            semgrep_bin, "scan",
            "--config", ruleset,
            "--json",
            "--quiet",
            "--timeout", str(timeout),
        ]
        for ex in exclude_paths:
            cmd.extend(["--exclude", ex])
        cmd.append(str(target))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30,
            )
        except subprocess.TimeoutExpired:
            result.findings.append(Finding(
                plugin=self.name,
                title="Semgrep scan timed out",
                severity=Severity.INFO,
                description=f"Scan exceeded {timeout + 30}s and was aborted.",
                remediation="Increase 'sast.timeout' in secureaudit.yml or scope the scan to fewer paths.",
            ))
            return result
        except Exception as exc:
            result.findings.append(Finding(
                plugin=self.name,
                title="Semgrep execution failed",
                severity=Severity.INFO,
                description=str(exc),
            ))
            return result

        if not proc.stdout.strip():
            result.findings.append(Finding(
                plugin=self.name,
                title="Semgrep produced no output",
                severity=Severity.INFO,
                description=proc.stderr[:300] if proc.stderr else "No output from semgrep.",
            ))
            return result

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            result.findings.append(Finding(
                plugin=self.name,
                title="Could not parse Semgrep output",
                severity=Severity.INFO,
                description="Semgrep output was not valid JSON.",
            ))
            return result

        for item in data.get("results", []):
            check_id = item.get("check_id", "unknown-rule")
            extra = item.get("extra", {})
            semgrep_severity = extra.get("severity", "WARNING")
            severity = _SEVERITY_MAP.get(semgrep_severity, Severity.MEDIUM)

            # Escalate known-critical patterns
            if any(hint in check_id.lower() for hint in _CRITICAL_HINTS):
                if severity in (Severity.MEDIUM, Severity.LOW):
                    severity = Severity.HIGH
                elif severity == Severity.HIGH:
                    severity = Severity.CRITICAL

            message = extra.get("message", "Potential vulnerability detected")
            path = item.get("path", "")
            try:
                rel_path = str(Path(path).relative_to(target))
            except ValueError:
                rel_path = path
            line = item.get("start", {}).get("line")

            rule_url = extra.get("metadata", {}).get(
                "source", f"https://semgrep.dev/r/{check_id}"
            )

            result.findings.append(Finding(
                plugin=self.name,
                title=f"SAST: {check_id.split('.')[-1]}",
                severity=severity,
                description=message[:300],
                file=rel_path,
                line=line,
                evidence=extra.get("lines", "")[:200],
                remediation=extra.get("metadata", {}).get(
                    "fix", "Review the flagged code and apply secure coding practices."
                ),
                reference=rule_url,
                extra={"rule_id": check_id, "owasp": extra.get("metadata", {}).get("owasp")},
            ))

        # Report scan errors from semgrep itself (e.g. parse errors in target files)
        scan_errors = data.get("errors", [])
        if scan_errors and cfg.get("report_scan_errors", False):
            result.findings.append(Finding(
                plugin=self.name,
                title=f"Semgrep reported {len(scan_errors)} file(s) it could not fully parse",
                severity=Severity.INFO,
                description="Some files may have incomplete analysis due to syntax issues.",
            ))

        if not result.findings:
            result.findings.append(Finding(
                plugin=self.name,
                title="No SAST findings",
                severity=Severity.INFO,
                description=f"Semgrep ({ruleset}) found no vulnerability patterns.",
            ))

        return result

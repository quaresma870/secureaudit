"""
SAST plugin — static application security testing via Semgrep.

Detects code-level vulnerability patterns: SQL injection, command injection,
path traversal, SSRF, insecure deserialization, hardcoded crypto, etc.

Runs entirely locally — no code is sent to any cloud service.
Gracefully degrades to an INFO finding if the `semgrep` binary is not installed.

Supports incremental scanning: when a cache is attached (see
secureaudit/core/cache.py), only files whose content hash changed since the
last run are actually passed to semgrep — unchanged files reuse cached
results, and a fully cache-hit run skips invoking semgrep altogether.
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

        if self.cache is not None:
            findings = self._run_with_cache(target, semgrep_bin, ruleset, timeout, exclude_paths)
        else:
            findings = self._run_semgrep([target], semgrep_bin, ruleset, timeout, exclude_paths, target)

        if findings is None:
            result.findings.append(Finding(
                plugin=self.name,
                title="Semgrep scan failed or timed out",
                severity=Severity.INFO,
                description="See plugin logs / increase 'sast.timeout' in secureaudit.yml.",
            ))
            return result

        result.findings = findings

        if not result.findings:
            result.findings.append(Finding(
                plugin=self.name,
                title="No SAST findings",
                severity=Severity.INFO,
                description=f"Semgrep ({ruleset}) found no vulnerability patterns.",
            ))

        return result

    # ── Incremental scanning ──────────────────────────────────────────────────

    def _collect_candidate_files(self, target: Path, exclude_paths: set, max_size: int) -> list[Path]:
        from secureaudit.core.cache import CACHE_DIR_NAME

        files = []
        for f in target.rglob("*"):
            if not f.is_file():
                continue
            if CACHE_DIR_NAME in f.parts:
                continue  # never scan our own cache, regardless of user exclude_paths config
            if any(part in exclude_paths for part in f.parts):
                continue
            try:
                if f.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            files.append(f)
        return files

    def _run_with_cache(
        self, target: Path, semgrep_bin: str, ruleset: str, timeout: int, exclude_paths: list[str],
    ) -> list[Finding] | None:
        from secureaudit.core.cache import cache_key, hash_config, hash_file

        cfg = self.plugin_config
        max_size = cfg.get("max_file_size_kb", 1024) * 1024
        files = self._collect_candidate_files(target, set(exclude_paths), max_size)

        config_hash = hash_config({"ruleset": ruleset, **cfg})
        cached_findings: list[Finding] = []
        to_scan: list[Path] = []
        key_by_file: dict[str, str] = {}

        for f in files:
            file_hash = hash_file(f)
            if file_hash is None:
                to_scan.append(f)
                continue
            key = cache_key(self.name, self.schema_version, config_hash, file_hash)
            cached = self.cache.get(key)
            if cached is not None:
                cached_findings.extend(Finding.from_dict(d) for d in cached)
            else:
                to_scan.append(f)
                key_by_file[str(f)] = key

        if not to_scan:
            # Every candidate file was a cache hit — semgrep is never invoked.
            return cached_findings

        fresh = self._run_semgrep(to_scan, semgrep_bin, ruleset, timeout, [], target)
        if fresh is None:
            # The incremental (file-list) invocation failed — fall back to a
            # full directory scan rather than silently losing coverage.
            return self._run_semgrep([target], semgrep_bin, ruleset, timeout, exclude_paths, target)

        # Group fresh findings by the file they belong to so each scanned
        # file gets its own cache entry — including files with zero findings,
        # otherwise a clean file would never become a cache hit.
        findings_by_file: dict[str, list[Finding]] = {str(p): [] for p in to_scan}
        for finding in fresh:
            if finding.file is None:
                continue
            abs_path = str(target / finding.file)
            if abs_path in findings_by_file:
                findings_by_file[abs_path].append(finding)

        for f in to_scan:
            key = key_by_file.get(str(f))
            if key:
                self.cache.set(key, [fnd.to_dict() for fnd in findings_by_file.get(str(f), [])])

        return cached_findings + fresh

    # ── Semgrep invocation + parsing ──────────────────────────────────────────

    def _run_semgrep(
        self,
        scan_targets: list[Path],
        semgrep_bin: str,
        ruleset: str,
        timeout: int,
        exclude_paths: list[str],
        base: Path,
    ) -> list[Finding] | None:
        """Run semgrep against either a single directory or an explicit file
        list. Returns None on failure/timeout so the caller can decide how to
        degrade (e.g. fall back to a full scan)."""
        cmd = [
            semgrep_bin, "scan",
            "--config", ruleset,
            "--json",
            "--quiet",
            "--timeout", str(timeout),
        ]
        for ex in exclude_paths:
            cmd.extend(["--exclude", ex])
        cmd.extend(str(p) for p in scan_targets)

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)
        except Exception:
            return None

        if not proc.stdout.strip():
            return []

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return None

        findings: list[Finding] = []
        for item in data.get("results", []):
            check_id = item.get("check_id", "unknown-rule")
            extra = item.get("extra", {})
            semgrep_severity = extra.get("severity", "WARNING")
            severity = _SEVERITY_MAP.get(semgrep_severity, Severity.MEDIUM)

            if any(hint in check_id.lower() for hint in _CRITICAL_HINTS):
                if severity in (Severity.MEDIUM, Severity.LOW):
                    severity = Severity.HIGH
                elif severity == Severity.HIGH:
                    severity = Severity.CRITICAL

            message = extra.get("message", "Potential vulnerability detected")
            path = item.get("path", "")
            try:
                rel_path = str(Path(path).relative_to(base))
            except ValueError:
                rel_path = path
            line = item.get("start", {}).get("line")

            rule_url = extra.get("metadata", {}).get("source", f"https://semgrep.dev/r/{check_id}")

            findings.append(Finding(
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

        return findings

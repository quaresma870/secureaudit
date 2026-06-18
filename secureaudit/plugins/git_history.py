"""
Git history plugin — scans git commit history for exposed secrets.

Detects secrets that were committed and later removed from the working tree
but remain accessible in git history.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from secureaudit.core.models import Finding, PluginResult, Severity
from secureaudit.plugins import BasePlugin, register

# Re-use secret patterns from the secrets plugin
_PATTERNS: list[tuple[str, re.Pattern, Severity]] = [
    ("AWS Access Key",      re.compile(r"AKIA[0-9A-Z]{16}"),                      Severity.CRITICAL),
    ("GitHub Token",        re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),        Severity.CRITICAL),
    ("Private Key Header",  re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("Slack Webhook",       re.compile(r"hooks\.slack\.com/services/T[A-Z0-9]+/"), Severity.HIGH),
    ("Generic API Key",     re.compile(r"api[_\-]?key\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})", re.I), Severity.HIGH),
    ("Hardcoded Password",  re.compile(r"password\s*[=:]\s*['\"]([^'\"]{8,})['\"]", re.I), Severity.HIGH),
    ("DB Connection String", re.compile(r"(?:postgresql|mysql|mongodb)://[^:]+:[^@\s]{4,}@", re.I), Severity.HIGH),
]


@register
class GitHistoryPlugin(BasePlugin):
    name = "git_history"
    description = "Scan git commit history for secrets that were later removed"

    def audit(self, target: str | Path) -> PluginResult:
        result = PluginResult(plugin=self.name)
        target = Path(target)

        # Check this is a git repo
        git_dir = target / ".git"
        if not git_dir.exists():
            result.findings.append(Finding(
                plugin=self.name,
                title="Not a git repository",
                severity=Severity.INFO,
                description="Target is not a git repository — git history scan skipped.",
            ))
            return result

        cfg = self.plugin_config
        max_commits = cfg.get("max_commits", 200)
        since_days = cfg.get("since_days", 90)

        # Get commits to scan
        commits = self._get_commits(target, max_commits, since_days)
        if not commits:
            result.findings.append(Finding(
                plugin=self.name,
                title="No commits found in history window",
                severity=Severity.INFO,
                description=f"No commits found in the last {since_days} days.",
            ))
            return result

        # Scan each commit's diff
        seen: set[str] = set()
        findings_count = 0
        max_findings = cfg.get("max_findings", 50)

        for commit_sha, author, date_str, message in commits:
            if findings_count >= max_findings:
                break

            diff = self._get_commit_diff(target, commit_sha)
            if not diff:
                continue

            for line in diff.splitlines():
                # Only scan added lines (prefixed with +)
                if not line.startswith("+") or line.startswith("+++"):
                    continue

                content = line[1:]
                for name, pattern, severity in _PATTERNS:
                    if pattern.search(content):
                        dedup_key = f"{commit_sha}:{name}:{content[:60]}"
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)
                        findings_count += 1

                        result.findings.append(Finding(
                            plugin=self.name,
                            title=f"Historical secret: {name}",
                            severity=severity,
                            description=(
                                f"{name} found in git history (commit {commit_sha[:8]}).\n"
                                f"Even though it may have been removed from the working tree, "
                                f"it remains accessible in git history."
                            ),
                            evidence=(
                                f"Commit: {commit_sha[:8]}\n"
                                f"Author: {author}\n"
                                f"Date: {date_str}\n"
                                f"Message: {message[:80]}\n"
                                f"Line: {content[:120]}"
                            ),
                            remediation=(
                                "1. Immediately rotate/revoke the exposed credential.\n"
                                "2. Purge from history: use 'git filter-repo' or BFG Repo Cleaner.\n"
                                "3. Force-push and invalidate all existing clones.\n"
                                "4. Add the pattern to .gitignore and pre-commit hooks."
                            ),
                            reference="https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
                            extra={
                                "commit": commit_sha,
                                "author": author,
                                "date": date_str,
                            },
                        ))

        if not result.findings:
            result.findings.append(Finding(
                plugin=self.name,
                title="No secrets found in git history",
                severity=Severity.INFO,
                description=(
                    f"Scanned {len(commits)} commits "
                    f"(last {since_days} days, max {max_commits}). No secrets detected."
                ),
            ))

        return result

    def _get_commits(
        self, target: Path, max_commits: int, since_days: int
    ) -> list[tuple[str, str, str, str]]:
        """Return list of (sha, author, date, message) tuples."""
        try:
            result = subprocess.run(
                [
                    "git", "log",
                    f"--since={since_days} days ago",
                    f"--max-count={max_commits}",
                    "--format=%H|%an|%ad|%s",
                    "--date=short",
                ],
                cwd=target,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return []
            commits = []
            for line in result.stdout.splitlines():
                parts = line.split("|", 3)
                if len(parts) == 4:
                    commits.append(tuple(parts))
            return commits
        except Exception:
            return []

    def _get_commit_diff(self, target: Path, sha: str) -> str:
        """Get the unified diff for a single commit."""
        try:
            result = subprocess.run(
                ["git", "show", "--format=", "-U0", sha, "--", "."],
                cwd=target,
                capture_output=True,
                text=True,
                timeout=15,
            )
            return result.stdout if result.returncode == 0 else ""
        except Exception:
            return ""

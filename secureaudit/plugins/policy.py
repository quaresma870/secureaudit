"""
Policy plugin — checks compliance with security policies:
SSL certificate expiry, firewall status, Docker security, .gitignore completeness.
"""

from __future__ import annotations

import re
from pathlib import Path

from secureaudit.core.models import Finding, PluginResult, Severity
from secureaudit.plugins import BasePlugin, register

_GITIGNORE_REQUIRED = [
    (".env", "Environment files with secrets"),
    (".env.local", "Local environment overrides"),
    ("*.pem", "PEM certificate/key files"),
    ("*.key", "Private key files"),
    ("terraform.tfvars", "Terraform variable files with secrets"),
    ("*.tfstate", "Terraform state files"),
    (".vault_pass", "Ansible vault password file"),
    ("node_modules/", "Node.js dependencies (large, should not be committed)"),
    ("__pycache__/", "Python bytecode cache"),
    (".DS_Store", "macOS metadata files"),
]


@register
class PolicyPlugin(BasePlugin):
    name = "policy"
    description = "Check security policy compliance: .gitignore, Docker, dependency files"

    def audit(self, target: str | Path) -> PluginResult:
        target = Path(target)
        result = PluginResult(plugin=self.name)

        result.findings.extend(self._check_gitignore(target))
        result.findings.extend(self._check_dockerfile(target))
        result.findings.extend(self._check_dependency_pinning(target))
        result.findings.extend(self._check_ci_security(target))

        info_only = all(f.severity == Severity.INFO for f in result.findings)
        if not result.findings or info_only:
            result.findings.append(Finding(
                plugin=self.name,
                title="Policy checks passed",
                severity=Severity.INFO,
                description="No policy violations detected.",
            ))

        return result

    def _check_gitignore(self, target: Path) -> list[Finding]:
        findings = []
        gitignore = target / ".gitignore"
        if not gitignore.exists():
            findings.append(Finding(
                plugin=self.name,
                title=".gitignore missing",
                severity=Severity.MEDIUM,
                description="No .gitignore found — sensitive files may be accidentally committed.",
                remediation="Create a .gitignore file. Use gitignore.io to generate one for your stack.",
            ))
            return findings

        content = gitignore.read_text(errors="ignore")
        for pattern, description in _GITIGNORE_REQUIRED:
            # Check if pattern or equivalent is present
            pattern_base = pattern.replace("/", "").replace("*.", "").replace("*", "")
            if pattern not in content and pattern_base not in content:
                findings.append(Finding(
                    plugin=self.name,
                    title=f".gitignore missing: {pattern}",
                    severity=Severity.LOW,
                    description=f"{description} not in .gitignore.",
                    file=".gitignore",
                    remediation=f"Add '{pattern}' to .gitignore",
                ))

        return findings

    def _check_dockerfile(self, target: Path) -> list[Finding]:
        dockerfiles = list(target.rglob("Dockerfile")) + list(target.rglob("Dockerfile.*"))
        exclude_paths = set(self.config.exclude_paths)
        from secureaudit.core.cache import CACHE_DIR_NAME
        candidates = [
            df for df in dockerfiles
            if CACHE_DIR_NAME not in df.parts and not any(part in exclude_paths for part in df.parts)
        ]

        if self.cache is not None:
            from secureaudit.core.cache import scan_with_cache
            return scan_with_cache(self, candidates, lambda f: self._check_dockerfile_one(f, target))

        findings = []
        for df in candidates:
            findings.extend(self._check_dockerfile_one(df, target))
        return findings

    def _check_dockerfile_one(self, df: Path, target: Path) -> list[Finding]:
        findings = []
        content = df.read_text(errors="ignore")
        lines = content.splitlines()
        rel = str(df.relative_to(target))

        # Running as root
        has_user = any(line.strip().upper().startswith("USER ") for line in lines)
        if not has_user:
            findings.append(Finding(
                plugin=self.name,
                title=f"Dockerfile runs as root: {rel}",
                severity=Severity.HIGH,
                description="No USER instruction found — container runs as root.",
                file=rel,
                remediation="Add 'USER nonroot' or create a dedicated user in your Dockerfile.",
                reference="https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user",
            ))

        # Pinned base image
        from_lines = [ln.strip() for ln in lines if ln.strip().upper().startswith("FROM ")]
        for from_line in from_lines:
            if ":latest" in from_line or (
                ":" not in from_line.split()[-1] and "@" not in from_line
            ):
                findings.append(Finding(
                    plugin=self.name,
                    title=f"Unpinned base image: {rel}",
                    severity=Severity.MEDIUM,
                    description=f"'{from_line}' uses latest or unpinned tag — builds may be unreproducible.",
                    file=rel,
                    evidence=from_line,
                    remediation="Pin to a specific version: e.g. 'FROM python:3.11.9-slim'",
                ))

        # ADD vs COPY
        if re.search(r"^\s*ADD\s+(?!http)", content, re.MULTILINE):
            findings.append(Finding(
                plugin=self.name,
                title=f"ADD used instead of COPY: {rel}",
                severity=Severity.LOW,
                description="ADD has implicit behaviours (tar extraction, URL fetching). Prefer COPY.",
                file=rel,
                remediation="Replace ADD with COPY for local files.",
            ))

        return findings

    def _check_dependency_pinning(self, target: Path) -> list[Finding]:
        findings = []

        # requirements.txt — check for unpinned deps
        req = target / "requirements.txt"
        if req.exists():
            content = req.read_text(errors="ignore")
            unpinned = []
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if re.match(r"^[A-Za-z0-9_.\-]+==[0-9]", line):
                    continue  # pinned
                if re.match(r"^[A-Za-z0-9_.\-]+\s*$", line):
                    unpinned.append(line)

            if unpinned:
                findings.append(Finding(
                    plugin=self.name,
                    title="Unpinned Python dependencies",
                    severity=Severity.LOW,
                    description=f"{len(unpinned)} unpinned package(s) in requirements.txt",
                    file="requirements.txt",
                    evidence=", ".join(unpinned[:5]),
                    remediation="Pin all dependencies: run 'pip freeze > requirements.txt'",
                ))

        return findings

    def _check_ci_security(self, target: Path) -> list[Finding]:
        """Check GitHub Actions workflows for security issues."""
        workflows_dir = target / ".github" / "workflows"
        if not workflows_dir.exists():
            return []

        workflow_files = list(workflows_dir.glob("*.yml"))

        if self.cache is not None:
            from secureaudit.core.cache import scan_with_cache
            return scan_with_cache(self, workflow_files, lambda f: self._check_ci_security_one(f, target))

        findings = []
        for wf in workflow_files:
            findings.extend(self._check_ci_security_one(wf, target))
        return findings

    def _check_ci_security_one(self, wf: Path, target: Path) -> list[Finding]:
        findings = []
        content = wf.read_text(errors="ignore")
        rel = str(wf.relative_to(target))

        # Secrets in env (not via secrets context)
        if re.search(r"env:\s*\n(?:\s+\w+:\s*(?!.*\$\{\{).*\n)*\s+\w+:\s*['\"]?[A-Za-z0-9_]{16,}", content):
            findings.append(Finding(
                plugin=self.name,
                title=f"Possible hardcoded value in CI: {wf.name}",
                severity=Severity.MEDIUM,
                description="Workflow may contain hardcoded secrets in env block.",
                file=rel,
                remediation="Use ${{ secrets.MY_SECRET }} instead of hardcoded values.",
            ))

        # pull_request_target with checkout of PR code (dangerous)
        if "pull_request_target" in content and "actions/checkout" in content:
            if "ref" in content and "head" in content:
                findings.append(Finding(
                    plugin=self.name,
                    title=f"Dangerous pull_request_target in {wf.name}",
                    severity=Severity.HIGH,
                    description="pull_request_target + checkout of PR head ref can allow secret exfiltration.",
                    file=rel,
                    reference="https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
                ))

        return findings

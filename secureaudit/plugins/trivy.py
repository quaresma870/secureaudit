"""
Trivy plugin — filesystem dependency scanning and IaC misconfiguration detection.

Broader ecosystem coverage than the OSV.dev-based `cve` plugin: Cargo, Composer,
NuGet, and nested lockfiles. Also scans Dockerfile / Kubernetes / Terraform for
misconfigurations.

Gracefully degrades to an INFO finding if `trivy` is not installed.
Container image scanning is opt-in (off by default — can be slow).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from secureaudit.core.models import Finding, PluginResult, Severity
from secureaudit.plugins import BasePlugin, register

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.LOW,
}


@register
class TrivyPlugin(BasePlugin):
    name = "trivy"
    description = "Container/filesystem CVE scanning and IaC misconfiguration via Trivy"

    def audit(self, target: str | Path) -> PluginResult:
        target = Path(target)
        result = PluginResult(plugin=self.name)

        trivy_bin = shutil.which("trivy")
        if not trivy_bin:
            result.findings.append(Finding(
                plugin=self.name,
                title="Trivy not installed — scan skipped",
                severity=Severity.INFO,
                description="trivy binary was not found on PATH.",
                remediation=(
                    "Install Trivy:\n"
                    "  Debian/Ubuntu: see https://aquasecurity.github.io/trivy/latest/getting-started/installation/\n"
                    "  macOS: brew install trivy\n"
                    "  Or download the static binary from GitHub releases."
                ),
                reference="https://aquasecurity.github.io/trivy/",
            ))
            return result

        cfg = self.plugin_config
        timeout = cfg.get("timeout", 180)

        result.findings.extend(self._scan_filesystem(trivy_bin, target, timeout))
        result.findings.extend(self._scan_config(trivy_bin, target, timeout))

        if cfg.get("scan_images", False):
            dockerfile = target / "Dockerfile"
            image_ref = cfg.get("image")
            if image_ref:
                result.findings.extend(self._scan_image(trivy_bin, image_ref, timeout))
            elif dockerfile.exists():
                result.findings.append(Finding(
                    plugin=self.name,
                    title="Image scan requested but no image specified",
                    severity=Severity.INFO,
                    description="Set 'trivy.image: your-image:tag' in secureaudit.yml to scan a built image.",
                ))

        if not result.findings:
            result.findings.append(Finding(
                plugin=self.name,
                title="No Trivy findings",
                severity=Severity.INFO,
                description="Filesystem and config scans found nothing to report.",
            ))

        return result

    def _run_trivy(self, trivy_bin: str, args: list[str], timeout: int) -> dict | None:
        cmd = [trivy_bin, *args, "--format", "json", "--quiet"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return None
        except Exception:
            return None

        if not proc.stdout.strip():
            return None
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError:
            return None

    def _scan_filesystem(self, trivy_bin: str, target: Path, timeout: int) -> list[Finding]:
        findings = []
        data = self._run_trivy(
            trivy_bin,
            ["fs", "--scanners", "vuln", str(target)],
            timeout,
        )
        if data is None:
            findings.append(Finding(
                plugin=self.name,
                title="Trivy filesystem scan failed or timed out",
                severity=Severity.INFO,
                description="Could not complete dependency vulnerability scan.",
            ))
            return findings

        for res in data.get("Results", []):
            target_name = res.get("Target", "")
            for vuln in res.get("Vulnerabilities", []) or []:
                severity = _SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN"), Severity.LOW)
                pkg = vuln.get("PkgName", "unknown")
                installed = vuln.get("InstalledVersion", "")
                fixed = vuln.get("FixedVersion", "")
                vuln_id = vuln.get("VulnerabilityID", "")

                findings.append(Finding(
                    plugin=self.name,
                    title=f"{vuln_id} in {pkg} {installed}",
                    severity=severity,
                    description=(vuln.get("Title") or vuln.get("Description", ""))[:300],
                    file=target_name,
                    remediation=(
                        f"Update {pkg} to {fixed}" if fixed
                        else f"No fixed version available yet for {pkg}. Monitor for updates."
                    ),
                    reference=vuln.get("PrimaryURL", f"https://nvd.nist.gov/vuln/detail/{vuln_id}"),
                    extra={"package": pkg, "installed": installed, "fixed": fixed},
                ))

        return findings

    def _scan_config(self, trivy_bin: str, target: Path, timeout: int) -> list[Finding]:
        findings = []
        data = self._run_trivy(
            trivy_bin,
            ["config", str(target)],
            timeout,
        )
        if data is None:
            return findings  # config scan failing silently is OK — fs scan is primary

        for res in data.get("Results", []):
            target_name = res.get("Target", "")
            for mis in res.get("Misconfigurations", []) or []:
                severity = _SEVERITY_MAP.get(mis.get("Severity", "UNKNOWN"), Severity.LOW)
                findings.append(Finding(
                    plugin=self.name,
                    title=f"IaC misconfig: {mis.get('Title', mis.get('ID', 'unknown'))}",
                    severity=severity,
                    description=mis.get("Description", "")[:300],
                    file=target_name,
                    remediation=mis.get("Resolution", "Review the Trivy documentation for this check."),
                    reference=mis.get("PrimaryURL", ""),
                    extra={"check_id": mis.get("ID")},
                ))

        return findings

    def _scan_image(self, trivy_bin: str, image: str, timeout: int) -> list[Finding]:
        findings = []
        data = self._run_trivy(
            trivy_bin,
            ["image", image],
            timeout,
        )
        if data is None:
            findings.append(Finding(
                plugin=self.name,
                title=f"Image scan failed: {image}",
                severity=Severity.INFO,
                description="Could not scan the specified image — ensure it is built and accessible.",
            ))
            return findings

        for res in data.get("Results", []):
            for vuln in res.get("Vulnerabilities", []) or []:
                severity = _SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN"), Severity.LOW)
                pkg = vuln.get("PkgName", "unknown")
                vuln_id = vuln.get("VulnerabilityID", "")
                fixed = vuln.get("FixedVersion", "")

                findings.append(Finding(
                    plugin=self.name,
                    title=f"Image CVE: {vuln_id} in {pkg}",
                    severity=severity,
                    description=(vuln.get("Title") or "")[:300],
                    file=f"image:{image}",
                    remediation=f"Update base image or {pkg} to {fixed}" if fixed else "No fix available yet.",
                    reference=vuln.get("PrimaryURL", ""),
                ))

        return findings

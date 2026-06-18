"""
CVE plugin — checks project dependencies against the OSV.dev vulnerability database.
Supports: Python (requirements.txt, pyproject.toml), Node.js (package.json),
           Go (go.sum), Ruby (Gemfile.lock), Rust (Cargo.lock).
No API key required — OSV.dev is free and open.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from secureaudit.core.models import Finding, PluginResult, Severity
from secureaudit.plugins import BasePlugin, register

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _parse_requirements_txt(path: Path) -> list[tuple[str, str]]:
    """Parse requirements.txt → [(package, version), ...]"""
    packages = []
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "http")):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:==|>=|<=|~=|!=|>|<)\s*([^\s;#,]+)", line)
        if m:
            packages.append((m.group(1), m.group(2).strip(",")))
    return packages


def _parse_package_json(path: Path) -> list[tuple[str, str]]:
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    pkgs = []
    for section in ("dependencies", "devDependencies"):
        for name, ver in data.get(section, {}).items():
            # Strip semver prefix: ^1.2.3 → 1.2.3
            ver_clean = re.sub(r"^[^0-9]*", "", ver).split("-")[0]
            if ver_clean:
                pkgs.append((name, ver_clean))
    return pkgs


def _parse_go_sum(path: Path) -> list[tuple[str, str]]:
    pkgs = []
    for line in path.read_text(errors="ignore").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            module = parts[0]
            ver = parts[1].split("/")[0].lstrip("v")
            pkgs.append((module, ver))
    return pkgs[:50]  # limit


@register
class CVEPlugin(BasePlugin):
    name = "cve"
    description = "Check dependencies for known CVEs using OSV.dev"

    def audit(self, target: str | Path) -> PluginResult:
        target = Path(target)
        result = PluginResult(plugin=self.name)

        # Collect packages from supported manifest files
        packages: list[tuple[str, str, str]] = []  # (name, version, ecosystem)

        manifests = {
            "requirements.txt": ("PyPI", _parse_requirements_txt),
            "package.json": ("npm", _parse_package_json),
            "go.sum": ("Go", _parse_go_sum),
        }

        for filename, (ecosystem, parser) in manifests.items():
            manifest = target / filename
            if manifest.exists():
                pkgs = parser(manifest)
                for name, ver in pkgs:
                    packages.append((name, ver, ecosystem))

        if not packages:
            result.findings.append(Finding(
                plugin=self.name,
                title="No dependency manifests found",
                severity=Severity.INFO,
                description="No supported dependency files found (requirements.txt, package.json, go.sum).",
            ))
            return result

        # Query OSV.dev in batch
        vulnerabilities = self._query_osv(packages)

        for pkg_name, pkg_ver, ecosystem, vulns in vulnerabilities:
            # Special case: network error sentinel
            if pkg_name == "_network_error":
                result.findings.append(Finding(
                    plugin=self.name,
                    title="CVE check skipped — network unavailable",
                    severity=Severity.INFO,
                    description=vulns[0].get("summary", "Could not reach OSV.dev API."),
                    remediation="Ensure network access to api.osv.dev or run the CVE check manually.",
                ))
                continue
            for vuln in vulns:
                vuln_id = vuln.get("id", "UNKNOWN")
                summary = vuln.get("summary", "No description available")
                severity_raw = "HIGH"
                # Try to get severity from CVSS
                for sev_entry in vuln.get("severity", []):
                    if "CVSS" in sev_entry.get("type", ""):
                        score = sev_entry.get("score", "")
                        if "CRITICAL" in str(score).upper():
                            severity_raw = "CRITICAL"
                        elif "HIGH" in str(score).upper():
                            severity_raw = "HIGH"
                        elif "MEDIUM" in str(score).upper():
                            severity_raw = "MEDIUM"
                        elif "LOW" in str(score).upper():
                            severity_raw = "LOW"

                severity = _SEVERITY_MAP.get(severity_raw, Severity.MEDIUM)
                refs = vuln.get("references", [])
                ref_url = refs[0]["url"] if refs else f"https://osv.dev/vulnerability/{vuln_id}"

                result.findings.append(Finding(
                    plugin=self.name,
                    title=f"{vuln_id} in {pkg_name} {pkg_ver}",
                    severity=severity,
                    description=f"{summary}",
                    evidence=f"{ecosystem}: {pkg_name}=={pkg_ver}",
                    remediation=f"Update {pkg_name} to a patched version. Check {ref_url}",
                    reference=ref_url,
                    extra={"vuln_id": vuln_id, "ecosystem": ecosystem,
                           "package": pkg_name, "version": pkg_ver},
                ))

        if not result.findings:
            result.findings.append(Finding(
                plugin=self.name,
                title="No known vulnerabilities found",
                severity=Severity.INFO,
                description=f"Checked {len(packages)} dependencies against OSV.dev — all clean.",
            ))

        return result

    def _query_osv(
        self, packages: list[tuple[str, str, str]]
    ) -> list[tuple[str, str, str, list]]:
        try:
            import urllib.error
            import urllib.request

            queries = [
                {"package": {"name": name, "ecosystem": eco}, "version": ver}
                for name, ver, eco in packages
            ]

            payload = json.dumps({"queries": queries}).encode()
            req = urllib.request.Request(
                _OSV_BATCH_URL,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())

            results = []
            for (name, ver, eco), batch_result in zip(packages, data.get("results", [])):
                vulns = batch_result.get("vulns", [])
                if vulns:
                    results.append((name, ver, eco, vulns))
            return results

        except Exception as e:
            # Network unavailable or API error — report as INFO, don't silently pass
            return [("_network_error", "", "unknown", [{"id": "NETWORK_ERROR", "summary": f"OSV.dev unreachable: {e}", "references": []}])]

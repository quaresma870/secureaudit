"""
CORS plugin — detects misconfigured Cross-Origin Resource Sharing policies.

Checks:
- Wildcard origin (*) combined with credentials
- Arbitrary origin reflection (any Origin echoed back)
- Null origin allowed
- Missing CORS headers on API endpoints
"""

from __future__ import annotations

import urllib.error
import urllib.request
from pathlib import Path

from secureaudit.core.models import Finding, PluginResult, Severity
from secureaudit.plugins import BasePlugin, register

_EVIL_ORIGIN = "https://evil.attacker.com"
_NULL_ORIGIN = "null"


@register
class CORSPlugin(BasePlugin):
    name = "cors"
    description = "Detect CORS misconfigurations (wildcard + credentials, origin reflection)"

    def audit(self, target: str | Path) -> PluginResult:
        result = PluginResult(plugin=self.name)

        urls = self.plugin_config.get("urls", [])
        if not urls:
            urls = self._detect_urls(Path(str(target)))

        if not urls:
            result.findings.append(Finding(
                plugin=self.name,
                title="No URLs configured for CORS check",
                severity=Severity.INFO,
                description="Add 'cors.urls' to secureaudit.yml to enable CORS scanning.",
                remediation="Example:\n  cors:\n    urls:\n      - https://api.example.com",
            ))
            return result

        timeout = self.plugin_config.get("timeout", 10)
        for url in urls:
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            result.findings.extend(self._check_url(url, timeout))

        if not any(f.severity != Severity.INFO for f in result.findings):
            result.findings.append(Finding(
                plugin=self.name,
                title="No CORS misconfigurations found",
                severity=Severity.INFO,
                description=f"CORS policy looks correct on {len(urls)} URL(s).",
            ))

        return result

    def _check_url(self, url: str, timeout: int) -> list[Finding]:
        findings = []

        # ── Test 1: arbitrary origin reflection ──────────────────────────────
        acao = self._get_cors_header(url, _EVIL_ORIGIN, timeout)
        if acao == _EVIL_ORIGIN:
            # Check if credentials are also allowed
            acac = self._get_acac_header(url, _EVIL_ORIGIN, timeout)
            if acac and acac.lower() == "true":
                findings.append(Finding(
                    plugin=self.name,
                    title=f"CORS: arbitrary origin reflected + credentials allowed — {url}",
                    severity=Severity.CRITICAL,
                    description=(
                        "The server reflects any Origin back in Access-Control-Allow-Origin "
                        "AND sets Access-Control-Allow-Credentials: true. "
                        "An attacker can make authenticated cross-origin requests from any domain."
                    ),
                    evidence=(
                        f"Request Origin: {_EVIL_ORIGIN}\n"
                        f"ACAO: {acao}\nACAC: {acac}"
                    ),
                    remediation=(
                        "Maintain an explicit allowlist of trusted origins. "
                        "Never reflect the request Origin without validation. "
                        "Example (nginx): add_header Access-Control-Allow-Origin 'https://yourdomain.com';"
                    ),
                    reference="https://portswigger.net/web-security/cors",
                ))
            else:
                findings.append(Finding(
                    plugin=self.name,
                    title=f"CORS: arbitrary origin reflected — {url}",
                    severity=Severity.HIGH,
                    description=(
                        "The server reflects any Origin back in Access-Control-Allow-Origin. "
                        "Without credentials this allows cross-origin reads of public data."
                    ),
                    evidence=f"Request Origin: {_EVIL_ORIGIN}\nACOO: {acao}",
                    remediation="Use an explicit origin allowlist instead of reflecting the request Origin.",
                    reference="https://portswigger.net/web-security/cors",
                ))

        # ── Test 2: wildcard + credentials ────────────────────────────────────
        acao_wild = self._get_cors_header(url, _EVIL_ORIGIN, timeout)
        if acao_wild == "*":
            acac = self._get_acac_header(url, _EVIL_ORIGIN, timeout)
            if acac and acac.lower() == "true":
                findings.append(Finding(
                    plugin=self.name,
                    title=f"CORS: wildcard origin + credentials — {url}",
                    severity=Severity.CRITICAL,
                    description=(
                        "Access-Control-Allow-Origin: * combined with "
                        "Access-Control-Allow-Credentials: true is rejected by browsers "
                        "but indicates a misconfiguration that may affect non-browser clients."
                    ),
                    evidence="ACAO: *\nACAC: true",
                    remediation="Replace wildcard with an explicit trusted origin list.",
                    reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSNotSupportingCredentials",
                ))

        # ── Test 3: null origin ────────────────────────────────────────────────
        acao_null = self._get_cors_header(url, _NULL_ORIGIN, timeout)
        if acao_null == "null":
            findings.append(Finding(
                plugin=self.name,
                title=f"CORS: null origin allowed — {url}",
                severity=Severity.HIGH,
                description=(
                    "The server allows requests with Origin: null. "
                    "This origin is sent by sandboxed iframes and local files — "
                    "it can be abused to bypass CORS restrictions."
                ),
                evidence="Request Origin: null → ACAO: null",
                remediation="Remove 'null' from the allowed origins list.",
                reference="https://portswigger.net/web-security/cors#whitelisting-null-origin-values",
            ))

        return findings

    def _get_cors_header(self, url: str, origin: str, timeout: int) -> str | None:
        try:
            req = urllib.request.Request(
                url,
                headers={"Origin": origin, "User-Agent": "SecureAudit/1.0"},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                return headers.get("access-control-allow-origin")
        except Exception:
            return None

    def _get_acac_header(self, url: str, origin: str, timeout: int) -> str | None:
        try:
            req = urllib.request.Request(
                url,
                headers={"Origin": origin, "User-Agent": "SecureAudit/1.0"},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                return headers.get("access-control-allow-credentials")
        except Exception:
            return None

    def _detect_urls(self, target: Path) -> list[str]:
        import re
        urls = []
        for cfg_file in ["secureaudit.yml", ".env", ".env.example"]:
            f = target / cfg_file
            if f.exists():
                content = f.read_text(errors="ignore")
                found = re.findall(r"https?://[a-zA-Z0-9.\-/]+", content)
                for url in found:
                    if "example.com" not in url and "localhost" not in url:
                        urls.append(url)
        return list(set(urls))[:5]

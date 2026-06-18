"""
HTTP plugin — checks security headers, SSL/TLS configuration, and redirects.
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from secureaudit.core.models import Finding, PluginResult, Severity
from secureaudit.plugins import BasePlugin, register

_REQUIRED_HEADERS: list[tuple[str, Severity, str, str]] = [
    (
        "Strict-Transport-Security",
        Severity.HIGH,
        "HSTS header missing — browsers may connect over HTTP.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    (
        "Content-Security-Policy",
        Severity.MEDIUM,
        "CSP header missing — XSS attacks may be possible.",
        "Add a Content-Security-Policy header tailored to your app.",
    ),
    (
        "X-Frame-Options",
        Severity.MEDIUM,
        "X-Frame-Options missing — clickjacking may be possible.",
        "Add: X-Frame-Options: SAMEORIGIN",
    ),
    (
        "X-Content-Type-Options",
        Severity.LOW,
        "X-Content-Type-Options missing — MIME sniffing attacks possible.",
        "Add: X-Content-Type-Options: nosniff",
    ),
    (
        "Referrer-Policy",
        Severity.LOW,
        "Referrer-Policy missing — referrer leakage possible.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
]

_DANGEROUS_HEADERS = [
    ("Server", Severity.LOW, "Server header exposes technology stack."),
    ("X-Powered-By", Severity.LOW, "X-Powered-By header exposes technology stack."),
    ("X-AspNet-Version", Severity.LOW, "X-AspNet-Version exposes framework version."),
]


@register
class HTTPPlugin(BasePlugin):
    name = "http"
    description = "Check HTTP security headers, SSL/TLS and redirect configuration"

    def audit(self, target: str | Path) -> PluginResult:
        result = PluginResult(plugin=self.name)
        target_str = str(target)
        cfg = self.plugin_config
        timeout = cfg.get("timeout", 10)

        # Extract URLs from config or detect from target directory
        urls = cfg.get("urls", [])
        if not urls:
            # Try to auto-detect from common config files
            urls = self._detect_urls(Path(target_str))

        if not urls:
            result.findings.append(Finding(
                plugin=self.name,
                title="No URLs configured",
                severity=Severity.INFO,
                description="Add 'http.urls' to secureaudit.yml to check HTTP headers.",
                remediation="Example: http:\n  urls:\n    - https://example.com",
            ))
            return result

        for url in urls:
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            result.findings.extend(self._check_url(url, timeout))

        if not any(f.severity != Severity.INFO for f in result.findings):
            result.findings.append(Finding(
                plugin=self.name,
                title="HTTP security headers look good",
                severity=Severity.INFO,
                description=f"All required security headers present on {len(urls)} URL(s).",
            ))

        return result

    def _check_url(self, url: str, timeout: int) -> list[Finding]:
        findings = []
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, headers={"User-Agent": "SecureAudit/1.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                status = resp.status

            # Check redirect HTTP → HTTPS
            if url.startswith("http://"):
                if status not in (301, 302, 307, 308):
                    findings.append(Finding(
                        plugin=self.name,
                        title=f"No HTTPS redirect on {url}",
                        severity=Severity.HIGH,
                        description="HTTP requests are not redirected to HTTPS.",
                        evidence=f"Status: {status}",
                        remediation="Configure nginx/apache to redirect HTTP to HTTPS.",
                    ))

            # Required headers
            for header, severity, description, remediation in _REQUIRED_HEADERS:
                if header.lower() not in headers:
                    findings.append(Finding(
                        plugin=self.name,
                        title=f"Missing header: {header}",
                        severity=severity,
                        description=description,
                        evidence=f"URL: {url}",
                        remediation=remediation,
                        reference="https://securityheaders.com",
                    ))

            # Dangerous headers
            for header, severity, description in _DANGEROUS_HEADERS:
                if header.lower() in headers:
                    findings.append(Finding(
                        plugin=self.name,
                        title=f"Information disclosure: {header}",
                        severity=severity,
                        description=description,
                        evidence=f"{header}: {headers[header.lower()]}",
                        remediation=f"Remove or obscure the {header} header in your server config.",
                    ))

            # SSL check
            if url.startswith("https://"):
                findings.extend(self._check_ssl(url, timeout))

        except ssl.SSLError as e:
            findings.append(Finding(
                plugin=self.name,
                title=f"SSL error on {url}",
                severity=Severity.CRITICAL,
                description=f"SSL/TLS error: {e}",
                remediation="Check your SSL certificate and configuration.",
            ))
        except urllib.error.URLError as e:
            findings.append(Finding(
                plugin=self.name,
                title=f"Connection failed: {url}",
                severity=Severity.INFO,
                description=f"Could not connect: {e.reason}",
            ))
        except Exception as e:
            findings.append(Finding(
                plugin=self.name,
                title=f"HTTP check error: {url}",
                severity=Severity.INFO,
                description=str(e),
            ))

        return findings

    def _check_ssl(self, url: str, timeout: int) -> list[Finding]:
        findings = []
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname
            port = parsed.port or 443

            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                __import__("socket").create_connection((host, port), timeout=timeout),
                server_hostname=host,
            ) as conn:
                cert = conn.getpeercert()
                not_after = cert.get("notAfter", "")
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
                    days_left = (expiry - datetime.now(UTC)).days
                    warn_days = self.plugin_config.get("ssl_expiry_warning_days", 30)
                    if days_left < 0:
                        findings.append(Finding(
                            plugin=self.name,
                            title=f"SSL certificate expired: {host}",
                            severity=Severity.CRITICAL,
                            description=f"Certificate expired {abs(days_left)} days ago.",
                            remediation="Renew the certificate immediately.",
                        ))
                    elif days_left < warn_days:
                        findings.append(Finding(
                            plugin=self.name,
                            title=f"SSL certificate expiring soon: {host}",
                            severity=Severity.HIGH,
                            description=f"Certificate expires in {days_left} days ({expiry.date()}).",
                            remediation="Renew the certificate before it expires.",
                        ))
        except Exception:
            pass  # SSL details not critical if connection worked

        return findings

    def _detect_urls(self, target: Path) -> list[str]:
        """Try to detect URLs from common config files."""
        urls = []
        for cfg_file in ["secureaudit.yml", ".env", ".env.example", "docker-compose.yml"]:
            f = target / cfg_file
            if f.exists():
                import re
                content = f.read_text(errors="ignore")
                found = re.findall(r"https?://[a-zA-Z0-9.\-/]+", content)
                for url in found:
                    if "example.com" not in url and "localhost" not in url:
                        urls.append(url)
        return list(set(urls))[:5]  # max 5 auto-detected

"""
Network plugin — scans for open ports and unexpected exposed services.
"""

from __future__ import annotations

import socket
from pathlib import Path

from secureaudit.core.models import Finding, PluginResult, Severity
from secureaudit.plugins import BasePlugin, register

_PORT_INFO: dict[int, tuple[str, Severity, str]] = {
    21:    ("FTP",         Severity.HIGH,   "FTP transmits credentials in plaintext. Use SFTP instead."),
    22:    ("SSH",         Severity.INFO,   "SSH port open — ensure key-based auth is enforced."),
    23:    ("Telnet",      Severity.CRITICAL, "Telnet transmits everything in plaintext. Disable immediately."),
    25:    ("SMTP",        Severity.MEDIUM, "SMTP open — ensure it requires authentication."),
    53:    ("DNS",         Severity.LOW,    "DNS port open — verify this is intentional."),
    80:    ("HTTP",        Severity.INFO,   "HTTP open — ensure redirects to HTTPS are in place."),
    110:   ("POP3",        Severity.MEDIUM, "POP3 may transmit credentials in plaintext."),
    143:   ("IMAP",        Severity.MEDIUM, "IMAP may transmit credentials in plaintext."),
    443:   ("HTTPS",       Severity.INFO,   "HTTPS open — expected for web servers."),
    445:   ("SMB",         Severity.HIGH,   "SMB open — high risk, associated with ransomware and lateral movement."),
    3306:  ("MySQL",       Severity.HIGH,   "MySQL exposed to network — restrict to localhost or VPN."),
    5432:  ("PostgreSQL",  Severity.HIGH,   "PostgreSQL exposed to network — restrict to localhost or VPN."),
    5900:  ("VNC",         Severity.HIGH,   "VNC open — use SSH tunnelling, never expose directly."),
    6379:  ("Redis",       Severity.CRITICAL, "Redis exposed — no auth by default. Restrict to localhost immediately."),
    8080:  ("HTTP-alt",    Severity.MEDIUM, "Alternative HTTP port open — verify this is intentional."),
    8443:  ("HTTPS-alt",   Severity.LOW,    "Alternative HTTPS port open."),
    27017: ("MongoDB",     Severity.HIGH,   "MongoDB exposed to network — restrict to localhost or VPN."),
}


@register
class NetworkPlugin(BasePlugin):
    name = "network"
    description = "Scan for open ports and unexpected exposed services"

    def audit(self, target: str | Path) -> PluginResult:
        result = PluginResult(plugin=self.name)
        cfg = self.plugin_config
        timeout = cfg.get("timeout", 1)
        ports = cfg.get("ports", list(_PORT_INFO.keys()))

        # Get host from config or try to resolve from target
        hosts = cfg.get("hosts", [])
        if not hosts:
            hosts = self._detect_hosts(Path(str(target)))

        if not hosts:
            result.findings.append(Finding(
                plugin=self.name,
                title="No hosts configured for port scanning",
                severity=Severity.INFO,
                description="Add 'network.hosts' to secureaudit.yml to enable port scanning.",
                remediation="Example:\n  network:\n    hosts:\n      - example.com\n      - 1.2.3.4",
            ))
            return result

        for host in hosts:
            open_ports = self._scan(host, ports, timeout)
            for port in open_ports:
                service, severity, description = _PORT_INFO.get(
                    port, (f"port-{port}", Severity.LOW, f"Port {port} is open.")
                )
                result.findings.append(Finding(
                    plugin=self.name,
                    title=f"Open port {port}/{service} on {host}",
                    severity=severity,
                    description=description,
                    evidence=f"{host}:{port} ({service})",
                    remediation=self._remediation(port),
                    extra={"host": host, "port": port, "service": service},
                ))

            if not open_ports:
                result.findings.append(Finding(
                    plugin=self.name,
                    title=f"No unexpected open ports on {host}",
                    severity=Severity.INFO,
                    description=f"Scanned {len(ports)} ports — none open from the checked list.",
                ))

        return result

    def _scan(self, host: str, ports: list[int], timeout: float) -> list[int]:
        open_ports = []
        for port in ports:
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    open_ports.append(port)
            except (TimeoutError, ConnectionRefusedError, OSError):
                pass
        return open_ports

    def _detect_hosts(self, target: Path) -> list[str]:
        import re
        hosts = []
        for f in [target / "secureaudit.yml", target / ".env", target / ".env.example"]:
            if f.exists():
                content = f.read_text(errors="ignore")
                found = re.findall(r"(?:HOST|DOMAIN|SERVER)\s*[=:]\s*([a-zA-Z0-9.\-]+)", content)
                for h in found:
                    if "." in h and "example" not in h and "localhost" not in h:
                        hosts.append(h)
        return list(set(hosts))[:3]

    def _remediation(self, port: int) -> str:
        remediations = {
            23: "Disable telnetd: systemctl disable telnet --now",
            21: "Use SFTP instead. Disable FTP: systemctl disable vsftpd --now",
            6379: "Bind Redis to localhost: bind 127.0.0.1 in redis.conf",
            3306: "Bind MySQL to localhost or use firewall: ufw deny 3306",
            5432: "Bind PostgreSQL to localhost: listen_addresses = 'localhost' in postgresql.conf",
            27017: "Bind MongoDB to localhost: bindIp: 127.0.0.1 in mongod.conf",
            445: "Disable SMB if not needed: systemctl disable smbd --now",
            5900: "Disable VNC or use SSH tunnel: ssh -L 5900:localhost:5900 user@host",
        }
        return remediations.get(port, f"Restrict port {port} via firewall if not needed: ufw deny {port}")

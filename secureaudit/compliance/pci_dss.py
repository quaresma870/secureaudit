"""
PCI-DSS v4.0 compliance mapping — best effort, a conservative subset of
Requirement 6 ("Develop and Maintain Secure Systems and Software") only.

Confirmed against the real, current PCI-DSS v4.0 control numbering
(cross-checked against multiple independent sources describing the
v3.2.1 -> v4.0 renumbering, not guessed) before mapping anything.

IMPORTANT — read before relying on this for an actual audit:
- Deliberately scoped to two controls this tool can genuinely observe from
  static source analysis. PCI-DSS Requirement 6 has many sub-requirements
  (6.2.2 developer training, 6.3.2 bespoke-software inventory, 6.3.3
  patch-timing SLAs, 6.4.1-6.4.6 change control and public-facing WAF/script
  management) that describe organisational process, documentation, or
  temporal/environmental state — none of that is observable from a repo
  checkout, which is all this tool ever looks at. Padding those into
  NOT_APPLICABLE filler rows would inflate the control count without adding
  real signal, the same reasoning cis_docker.py's docstring gives for its
  own Section-4-only scope.
- This is a best-effort mapping built from what our own plugins can
  observe. It is NOT a substitute for a real PCI-DSS assessment by a
  Qualified Security Assessor (QSA) and does NOT constitute a passing ASV
  scan or formal compliance certification. PCI-DSS compliance in practice
  covers organisational, network, and cardholder-data-environment scope
  this tool has no visibility into.
- A control marked PASS means "no relevant finding was raised by the
  plugins that exercise it" — it does not mean every aspect of that
  control was verified.
- Official standard: https://www.pcisecuritystandards.org (free registration
  required for the full PCI-DSS v4.0.1 document).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from secureaudit.compliance.owasp_asvs import ComplianceStatus
from secureaudit.core.models import AuditResult, Finding, Severity


@dataclass(frozen=True)
class PCIControl:
    id: str
    section: str
    description: str
    plugins: tuple[str, ...]
    matcher: Callable[[Finding], bool] | None = field(default=None)

    def applies_to(self, finding: Finding) -> bool:
        if finding.severity == Severity.INFO:
            return False
        if finding.plugin not in self.plugins:
            return False
        if self.matcher is None:
            return True
        return self.matcher(finding)


def _sast_rule_contains(*keywords: str) -> Callable[[Finding], bool]:
    """A sast Finding's title is 'SAST: {check_id-suffix}' (secureaudit/
    plugins/sast.py) — matches if any keyword appears in that suffix,
    case-insensitively. Mirrors owasp_asvs.py's own private helper of the
    same name and purpose; not imported across modules since compliance
    modules deliberately don't share private matcher internals with each
    other (only the public ComplianceStatus enum), keeping each framework
    module self-contained and independently auditable."""
    def _match(f: Finding) -> bool:
        if f.plugin != "sast":
            return False
        title_lower = f.title.lower()
        return any(kw.lower() in title_lower for kw in keywords)
    return _match


def _is_cve_style_finding(f: Finding) -> bool:
    """True for cve plugin findings, and trivy findings that are CVE
    lookups specifically (not IaC misconfig or image-scan-failed rows,
    which trivy.py also emits under the same plugin name)."""
    if f.plugin == "cve":
        return True
    if f.plugin == "trivy":
        return "package" in f.extra or "check_id" not in f.extra and "CVE" in f.title
    return False


CONTROLS: list[PCIControl] = [
    PCIControl(
        "6.2.4", "Requirement 6: Develop and Maintain Secure Systems and Software",
        "Software engineering techniques or other methods are defined and in "
        "use to prevent or mitigate common software attacks and related "
        "vulnerabilities in bespoke and custom software — including "
        "injection flaws (SQL, OS command, LDAP, XPath) and cross-site "
        "scripting (XSS).",
        ("sast",),
        matcher=_sast_rule_contains(
            "sql-injection", "sqli", "command-injection", "code-injection", "xss",
        ),
    ),
    PCIControl(
        "6.3.1", "Requirement 6: Develop and Maintain Secure Systems and Software",
        "Security vulnerabilities are identified using industry-recognized "
        "sources for vulnerability information (e.g. CVE feeds), assigned a "
        "risk ranking, and covers vulnerabilities affecting bespoke and "
        "custom software, as well as third-party software.",
        ("cve", "trivy"),
        matcher=_is_cve_style_finding,
    ),
]


def evaluate(result: AuditResult) -> list[dict]:
    """Evaluate the two in-scope PCI-DSS v4.0 controls against the plugins
    actually run and the active (non-suppressed) findings in `result`.
    Same {id, chapter, description, status, evidence_count} shape as
    owasp_asvs.evaluate() and cis_docker.evaluate() — "chapter" here
    holds the PCI-DSS requirement name.

    Same NOT_APPLICABLE convention already established by cis_docker.py
    (and the bug found and fixed there): fires only when the control's
    plugin(s) didn't run at all — not based on any heuristic about
    whether relevant files exist, which cis_docker.py's own history shows
    is a genuinely easy distinction to get wrong (PASS incorrectly turning
    into NOT_APPLICABLE) if attempted."""
    ran_plugins = {pr.plugin for pr in result.plugin_results}
    all_findings = result.all_findings

    rows: list[dict] = []
    for control in CONTROLS:
        if not (set(control.plugins) & ran_plugins):
            rows.append({
                "id": control.id, "chapter": control.section,
                "description": control.description,
                "status": ComplianceStatus.NOT_APPLICABLE.value, "evidence_count": 0,
            })
            continue

        matching = [f for f in all_findings if control.applies_to(f)]
        status = ComplianceStatus.FAIL if matching else ComplianceStatus.PASS
        rows.append({
            "id": control.id, "chapter": control.section,
            "description": control.description,
            "status": status.value, "evidence_count": len(matching),
        })

    return rows

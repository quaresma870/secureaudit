"""
OWASP ASVS v4.0.3 compliance mapping — best effort.

Maps SecureAudit findings to OWASP Application Security Verification Standard
(ASVS) v4.0.3 requirements, so a raw finding count can be read as "which
controls does this codebase currently satisfy."

IMPORTANT — read before relying on this for an actual audit:
- This is a best-effort mapping built from what our plugins can observe.
  It is NOT a substitute for a full ASVS assessment and does NOT constitute
  formal compliance certification.
- Requirement descriptions below are paraphrased summaries for readability,
  not verbatim quotes from the standard. Always verify the exact requirement
  text and applicability against the official standard before using this for
  compliance reporting to a third party:
  https://github.com/OWASP/ASVS/tree/master/4.0
- A control marked PASS means "no relevant finding was raised by the plugins
  that exercise it" — it does not mean every aspect of that requirement was
  verified. A control marked NOT_APPLICABLE means none of the plugins that
  could provide evidence for it were run in this scan.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

from secureaudit.core.models import AuditResult, Finding, Severity


class ComplianceStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class ASVSControl:
    id: str
    chapter: str
    description: str
    plugins: tuple[str, ...]
    # Narrows which findings from the listed plugin(s) count as evidence for
    # this specific control. None means "any finding from these plugins
    # counts" — appropriate when the whole plugin maps cleanly to one control.
    matcher: Callable[[Finding], bool] | None = field(default=None)

    def applies_to(self, finding: Finding) -> bool:
        # INFO is this codebase's consistent convention for "nothing wrong" or
        # contextual notices (e.g. "No malware detected", "No CORS
        # misconfigurations found") — never treat one as failure evidence,
        # regardless of which plugin produced it or whether a matcher is set.
        if finding.severity == Severity.INFO:
            return False
        if finding.plugin not in self.plugins:
            return False
        if self.matcher is None:
            return True
        return self.matcher(finding)


# ── Matcher helpers — built on exact title prefixes / extra-dict keys we ────
# ── control in our own plugin code, not fragile guesswork.                ──

def _http_missing_hsts(f: Finding) -> bool:
    return f.title == "Missing header: Strict-Transport-Security"


def _http_missing_csp(f: Finding) -> bool:
    return f.title == "Missing header: Content-Security-Policy"


def _http_missing_other_header(f: Finding) -> bool:
    return f.title.startswith("Missing header:") and not (
        _http_missing_hsts(f) or _http_missing_csp(f)
    )


def _http_tls_issue(f: Finding) -> bool:
    return f.title.startswith(("SSL certificate", "No HTTPS redirect"))


def _sast_rule_contains(*keywords: str) -> Callable[[Finding], bool]:
    def _match(f: Finding) -> bool:
        rule_id = str(f.extra.get("rule_id", "")).lower()
        return any(k in rule_id for k in keywords)
    return _match


def _trivy_is_cve_finding(f: Finding) -> bool:
    return f.plugin == "trivy" and "package" in f.extra


def _trivy_is_iac_finding(f: Finding) -> bool:
    return f.plugin == "trivy" and "check_id" in f.extra


def _dependency_freshness(f: Finding) -> bool:
    if f.plugin == "cve":
        return True
    if f.plugin == "trivy":
        return _trivy_is_cve_finding(f)
    if f.plugin == "policy":
        return "unpinned" in f.title.lower()
    return False


def _container_hardening(f: Finding) -> bool:
    if f.plugin == "trivy":
        return _trivy_is_iac_finding(f)
    if f.plugin == "policy":
        title_lower = f.title.lower()
        return any(s in title_lower for s in ("dockerfile runs as root", "unpinned base image", "add used instead of copy"))
    return False


def _ci_pipeline_hardening(f: Finding) -> bool:
    title_lower = f.title.lower()
    return "hardcoded value in ci" in title_lower or "pull_request_target" in title_lower


# ── Control catalogue ─────────────────────────────────────────────────────────
# 15 controls across 9 plugins. See module docstring for the caveats that
# apply to every row below.

CONTROLS: list[ASVSControl] = [
    ASVSControl(
        "V6.4.1", "V6: Stored Cryptography",
        "Secrets (API keys, tokens, passwords, private keys) are managed via a "
        "vault or environment-based secret store, not hardcoded in source.",
        ("secrets",),
    ),
    ASVSControl(
        "V14.2.1", "V14: Configuration",
        "Third-party components and dependencies are kept up to date and free "
        "of known published vulnerabilities.",
        ("cve", "trivy", "policy"),
        matcher=_dependency_freshness,
    ),
    ASVSControl(
        "V1.14.6", "V1: Architecture, Design and Threat Modeling",
        "The build/CI pipeline includes automated verification that "
        "third-party components are free of known vulnerabilities.",
        ("cve", "trivy"),
        matcher=lambda f: f.plugin == "cve" or _trivy_is_cve_finding(f),
    ),
    ASVSControl(
        "V14.4.5", "V14: Configuration",
        "HTTP Strict Transport Security (HSTS) is enforced on all HTTPS responses.",
        ("http",),
        matcher=_http_missing_hsts,
    ),
    ASVSControl(
        "V14.4.3", "V14: Configuration",
        "A Content Security Policy (CSP) is configured to mitigate XSS and "
        "data-injection attacks.",
        ("http",),
        matcher=_http_missing_csp,
    ),
    ASVSControl(
        "V14.4.1", "V14: Configuration",
        "HTTP responses set explicit, defensive security headers "
        "(X-Frame-Options, X-Content-Type-Options, Referrer-Policy).",
        ("http",),
        matcher=_http_missing_other_header,
    ),
    ASVSControl(
        "V9.1.1", "V9: Communications",
        "TLS is enforced for all client connectivity, with valid, "
        "non-expired certificates and no insecure HTTP fallback.",
        ("http",),
        matcher=_http_tls_issue,
    ),
    ASVSControl(
        "V14.5.3", "V14: Configuration",
        "CORS policy uses an explicit origin allow-list rather than "
        "reflecting arbitrary request origins.",
        ("cors",),
    ),
    ASVSControl(
        "V5.3.5", "V5: Validation, Sanitization and Encoding",
        "Inputs that reach interpreters (SQL, OS commands, etc.) are "
        "parameterised or otherwise validated against injection.",
        ("sast",),
        matcher=_sast_rule_contains("sql-injection", "sqli", "command-injection", "code-injection"),
    ),
    ASVSControl(
        "V5.3.4", "V5: Validation, Sanitization and Encoding",
        "Output is contextually encoded to prevent cross-site scripting (XSS).",
        ("sast",),
        matcher=_sast_rule_contains("xss"),
    ),
    ASVSControl(
        "V12.5.1", "V12: Files and Resources",
        "File path handling is protected against path/directory traversal.",
        ("sast",),
        matcher=_sast_rule_contains("path-traversal", "traversal"),
    ),
    ASVSControl(
        "V10.3.2", "V10: Malicious Code",
        "The codebase and its dependencies are verified free of known "
        "malware signatures.",
        ("malware",),
    ),
    ASVSControl(
        "V1.4.1", "V1: Architecture, Design and Threat Modeling",
        "Version control history does not retain secrets that were "
        "committed and later removed from the working tree.",
        ("git_history",),
    ),
    ASVSControl(
        "V14.1.3", "V14: Configuration",
        "Container build configuration follows hardening guidance: "
        "non-root user, pinned base images, no implicit ADD behaviours.",
        ("policy", "trivy"),
        matcher=_container_hardening,
    ),
    ASVSControl(
        "V14.3.2", "V14: Configuration",
        "CI/CD pipeline configuration does not hardcode secrets and avoids "
        "dangerous trigger/checkout combinations that risk secret exfiltration.",
        ("policy",),
        matcher=_ci_pipeline_hardening,
    ),
]


def evaluate(result: AuditResult) -> list[dict]:
    """Evaluate every ASVS control against the plugins actually run and the
    active (non-suppressed) findings in `result`.

    Returns a list of dicts: {id, chapter, description, status, evidence_count}
    """
    ran_plugins = {pr.plugin for pr in result.plugin_results}
    all_findings = result.all_findings

    rows: list[dict] = []
    for control in CONTROLS:
        if not (set(control.plugins) & ran_plugins):
            rows.append({
                "id": control.id,
                "chapter": control.chapter,
                "description": control.description,
                "status": ComplianceStatus.NOT_APPLICABLE.value,
                "evidence_count": 0,
            })
            continue

        matching = [f for f in all_findings if control.applies_to(f)]
        status = ComplianceStatus.FAIL if matching else ComplianceStatus.PASS
        rows.append({
            "id": control.id,
            "chapter": control.chapter,
            "description": control.description,
            "status": status.value,
            "evidence_count": len(matching),
        })

    return rows

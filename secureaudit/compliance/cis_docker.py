"""
CIS Docker Benchmark compliance mapping — best effort, Section 4 only.

Maps SecureAudit findings to CIS Docker Benchmark Section 4 ("Container
Images and Build File Configuration") controls — confirmed against the
benchmark's actual published control numbering (multiple independent
sources cross-checked, not guessed) before mapping anything to them.

IMPORTANT — read before relying on this for an actual audit:
- Deliberately scoped to Section 4 only. CIS Docker Benchmark's other
  sections (1: Host Configuration, 2: Docker Daemon Configuration,
  3: Docker Daemon Configuration Files, 5: Container Runtime,
  6/7: Operations/Swarm) require inspecting a LIVE Docker host/daemon —
  none of that is observable from static source code, which is all this
  tool ever looks at. Forcing those into NOT_APPLICABLE filler rows
  would pad the control count without adding any real signal; Section 4
  (Dockerfile/build-file content) is the one section that's actually
  knowable from a repo checkout.
- This is a best-effort mapping built from what our own plugins can
  observe. It is NOT a substitute for a full CIS-CAT assessment and does
  NOT constitute formal compliance certification.
- A control marked PASS means "no relevant finding was raised by the
  plugins that exercise it" — it does not mean every aspect of that
  control was verified. A control marked NOT_APPLICABLE means no
  Dockerfile was found in this scan at all (nothing to evaluate against).
- Official benchmark: https://www.cisecurity.org/benchmark/docker
  (free registration required to download the full PDF).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from secureaudit.compliance.owasp_asvs import ComplianceStatus
from secureaudit.core.models import AuditResult, Finding, Severity


@dataclass(frozen=True)
class CISControl:
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


def _is_dockerfile(finding: Finding) -> bool:
    return bool(finding.file) and "dockerfile" in finding.file.lower()


def _policy_title_prefix(prefix: str) -> Callable[[Finding], bool]:
    def _match(f: Finding) -> bool:
        return f.title.startswith(prefix)
    return _match


CONTROLS: list[CISControl] = [
    CISControl(
        "4.1", "Section 4: Container Images and Build File Configuration",
        "Create a user for the container — Dockerfiles should switch to a "
        "non-root USER before running the application.",
        ("policy",),
        matcher=_policy_title_prefix("Dockerfile runs as root:"),
    ),
    CISControl(
        "4.2", "Section 4: Container Images and Build File Configuration",
        "Use trusted, version-pinned base images rather than ':latest' or "
        "otherwise unpinned tags, which make builds non-reproducible and "
        "can silently pull in a different (and potentially vulnerable) "
        "image over time.",
        ("policy",),
        matcher=_policy_title_prefix("Unpinned base image:"),
    ),
    CISControl(
        "4.9", "Section 4: Container Images and Build File Configuration",
        "Use COPY instead of ADD in Dockerfiles — ADD's implicit remote-URL "
        "fetching and archive extraction are harder to audit than a plain "
        "file copy.",
        ("policy",),
        matcher=_policy_title_prefix("ADD used instead of COPY:"),
    ),
    CISControl(
        "4.10", "Section 4: Container Images and Build File Configuration",
        "Do not store secrets in Dockerfiles — credentials baked into a "
        "build file persist in image layer history even if removed in a "
        "later layer.",
        ("secrets",),
        matcher=_is_dockerfile,
    ),
]


def evaluate(result: AuditResult) -> list[dict]:
    """Evaluate every CIS Docker Benchmark Section 4 control against the
    plugins actually run and the active (non-suppressed) findings in
    `result`. Same {id, chapter, description, status, evidence_count}
    shape as owasp_asvs.evaluate() — "chapter" here holds the CIS
    section name, for a consistent column across compliance reports
    regardless of which framework produced them.

    Note on NOT_APPLICABLE: this only fires when the control's plugin
    didn't run at all (same convention as owasp_asvs.py) — not when no
    Dockerfile happens to exist in the repo. An earlier version tried to
    special-case "no Dockerfile found" as NOT_APPLICABLE by checking for
    *any* finding mentioning "dockerfile", but that's indistinguishable
    from "a Dockerfile exists and is fully compliant" (which has no such
    finding either) — caught this by actually running it against a
    clean, compliant Dockerfile and seeing PASS incorrectly turn into
    NOT_APPLICABLE, not by reasoning it through up front."""
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

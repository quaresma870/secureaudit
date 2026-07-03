"""
Compliance framework registry — extensible mapping of framework name to its
evaluate(result) -> list[dict] function. Add new frameworks by writing a
module with the same evaluate() signature and registering it here.
"""

from __future__ import annotations

from secureaudit.compliance import cis_docker, owasp_asvs, pci_dss

FRAMEWORKS = {
    "owasp-asvs": owasp_asvs.evaluate,
    "cis-docker": cis_docker.evaluate,
    "pci-dss": pci_dss.evaluate,
}

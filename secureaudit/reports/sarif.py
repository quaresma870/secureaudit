"""
SARIF 2.1.0 output — for GitHub Security tab integration.
Upload with: actions/upload-sarif or github/codeql-action/upload-sarif
"""

from __future__ import annotations

import json
from pathlib import Path

from secureaudit.core.models import AuditResult, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

_SARIF_SCORE = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFO: 0.0,
}


def write_sarif(result: AuditResult, path: str | Path) -> None:
    """Write a SARIF 2.1.0 report compatible with GitHub Security tab."""

    # Build rule list from unique findings
    rules_seen: dict[str, dict] = {}
    for finding in result.all_findings:
        rule_id = f"{finding.plugin}/{finding.title.replace(' ', '_').lower()}"
        if rule_id not in rules_seen:
            rules_seen[rule_id] = {
                "id": rule_id,
                "name": finding.title.replace(" ", ""),
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "helpUri": finding.reference or "https://github.com/quaresma870/secureaudit",
                "properties": {
                    "tags": [finding.plugin, finding.severity.value.lower()],
                    "precision": "high",
                    "problem.severity": finding.severity.value.lower(),
                    "security-severity": str(_SARIF_SCORE[finding.severity]),
                },
            }

    # Build results
    sarif_results = []
    for finding in result.all_findings:
        rule_id = f"{finding.plugin}/{finding.title.replace(' ', '_').lower()}"
        sarif_result: dict = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL[finding.severity],
            "message": {
                "text": finding.description
                + (f"\n\nRemediation: {finding.remediation}" if finding.remediation else "")
            },
        }

        if finding.file:
            sarif_result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file,
                            "uriBaseId": "%SRCROOT%",
                        },
                        **(
                            {
                                "region": {
                                    "startLine": finding.line,
                                    "snippet": {"text": finding.evidence or ""},
                                }
                            }
                            if finding.line
                            else {}
                        ),
                    }
                }
            ]

        sarif_results.append(sarif_result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecureAudit",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/quaresma870/secureaudit",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": sarif_results,
                "properties": {
                    "score": result.score,
                    "grade": result.grade,
                },
            }
        ],
    }

    Path(path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")

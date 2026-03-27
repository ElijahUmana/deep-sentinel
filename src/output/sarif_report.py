"""
SARIF (Static Analysis Results Interchange Format) output for DeepSentinel.
SARIF is the industry standard format for security analysis results.
Supports integration with GitHub Security, Azure DevOps, and other tools.
"""
import json
from datetime import datetime, timezone


def generate_sarif(findings: list, correlations: list, scan_metadata: dict) -> dict:
    """Generate a SARIF 2.1.0 report from DeepSentinel findings."""

    rules = {}
    results = []

    for finding in findings:
        cwe_id = finding.get("cwe_id", "CWE-000")
        severity = finding.get("severity", "MEDIUM").upper()

        # Create rule if not exists
        if cwe_id not in rules:
            rules[cwe_id] = {
                "id": cwe_id,
                "name": cwe_id.replace("-", ""),
                "shortDescription": {"text": finding.get("title", cwe_id)},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[-1]}.html",
                "properties": {"security-severity": _severity_to_score(severity)},
            }

        # Map cross-source context
        cross_source = []
        for corr in correlations:
            github_ref = corr.get("github_ref", "")
            file_path = finding.get("file_path", "")
            if file_path in github_ref or finding.get("title", "").lower() in corr.get("risk_note", "").lower():
                cross_source.append(corr)

        result = {
            "ruleId": cwe_id,
            "level": _severity_to_level(severity),
            "message": {
                "text": finding.get("description", finding.get("title", "")),
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.get("file_path", "unknown")},
                        "region": {"startLine": finding.get("line_number", 1)},
                    }
                }
            ],
            "properties": {
                "severity": severity,
                "source": finding.get("source", "llm_analysis"),
                "fix_suggestion": finding.get("fix_suggestion", finding.get("fix", "")),
                "cross_source_context": [c.get("risk_note", "") for c in cross_source],
                "cross_source_refs": [
                    {"slack": c.get("slack_ref", ""), "github": c.get("github_ref", "")}
                    for c in cross_source
                ],
            },
        }
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DeepSentinel",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/ElijahUmana/deep-sentinel",
                        "semanticVersion": "1.0.0",
                        "rules": list(rules.values()),
                        "properties": {
                            "description": "Cross-source security intelligence that finds what scanners miss",
                            "integrations": [
                                "Auth0 (identity + Token Vault + CIBA + FGA)",
                                "Airbyte (GitHub + Slack agent connectors)",
                                "Macroscope (codebase architecture)",
                                "Ghost (persistent Postgres)",
                                "TrueFoundry (AI Gateway)",
                                "Aerospike (real-time cache)",
                                "Overmind (OverClaw optimization)",
                            ],
                        },
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": scan_metadata.get("start_time", datetime.now(timezone.utc).isoformat()),
                        "endTimeUtc": scan_metadata.get("end_time", datetime.now(timezone.utc).isoformat()),
                        "properties": {
                            "scan_id": scan_metadata.get("scan_id", ""),
                            "repository": scan_metadata.get("repository", ""),
                            "cross_source_correlations": len(correlations),
                            "total_findings": len(findings),
                            "critical_count": sum(1 for f in findings if f.get("severity", "").upper() == "CRITICAL"),
                            "high_count": sum(1 for f in findings if f.get("severity", "").upper() == "HIGH"),
                        },
                    }
                ],
            }
        ],
    }

    return sarif


def _severity_to_level(severity: str) -> str:
    """Map severity to SARIF level."""
    mapping = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
    return mapping.get(severity.upper(), "warning")


def _severity_to_score(severity: str) -> str:
    """Map severity to security-severity score (CVSS-like)."""
    mapping = {"CRITICAL": "9.5", "HIGH": "7.5", "MEDIUM": "5.0", "LOW": "2.5"}
    return mapping.get(severity.upper(), "5.0")


def save_sarif(sarif: dict, filepath: str):
    """Save SARIF report to file."""
    with open(filepath, "w") as f:
        json.dump(sarif, f, indent=2)
    print(f"[SARIF] Report saved to {filepath}")

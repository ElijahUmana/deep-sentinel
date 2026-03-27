"""
DeepSentinel Risk Scorer — the unique differentiator.

Traditional scanners assign severity based on the CODE vulnerability.
DeepSentinel assigns risk based on code severity PLUS team context:
- Is the team AWARE of the vulnerability? (from Slack/Issues)
- Has it been DEFERRED? (conscious risk acceptance)
- Is it in a CRITICAL module? (from Macroscope architecture)
- Has it appeared BEFORE? (from Ghost historical data)

This produces a COMPOSITE RISK SCORE that no code-only scanner can compute.
"""


def compute_risk_score(finding: dict, correlations: list, historical: list, architecture: dict) -> dict:
    """
    Compute a composite risk score for a finding.

    Returns a dict with:
    - composite_score: 0-100 (higher = more urgent)
    - code_severity_score: from CWE severity
    - team_awareness_score: are they aware? (reduces urgency if yes, UNLESS deferred)
    - deferral_penalty: explicit deferral INCREASES risk (they know but aren't fixing)
    - architectural_multiplier: critical modules score higher
    - historical_frequency: repeated findings score higher
    - explanation: human-readable risk explanation
    """
    # 1. Code severity base score
    severity = finding.get("severity", "MEDIUM").upper()
    severity_scores = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 50, "LOW": 30}
    code_score = severity_scores.get(severity, 50)

    # 2. Team awareness from cross-source correlations
    file_path = finding.get("file_path", "")
    cwe_id = finding.get("cwe_id", "")

    awareness_score = 0
    deferral_penalty = 0
    related_correlations = []

    for corr in correlations:
        corr_text = f"{corr.get('risk_note', '')} {corr.get('github_ref', '')} {corr.get('context_text', '')}".lower()

        # Check if this correlation relates to this finding
        if file_path.lower() in corr_text or (cwe_id and cwe_id.lower() in corr_text):
            related_correlations.append(corr)
            corr_type = corr.get("type", "")

            if corr_type == "deferred_security_work":
                # Team KNOWS but DEFERRED — this is the WORST case
                # It means the risk was consciously accepted and is accumulating
                deferral_penalty += 15
                awareness_score += 5  # They're aware but that makes it worse

            elif corr_type == "known_issue_unresolved":
                # Known but not fixed — bad
                deferral_penalty += 10
                awareness_score += 5

            elif corr_type == "code_review_concern":
                # A reviewer flagged it — team partially aware
                awareness_score += 10
                deferral_penalty += 5  # Should have been fixed

    # 3. Architectural context
    arch = architecture.get(file_path, {})
    criticality = arch.get("criticality", "medium")
    arch_multiplier = {"high": 1.3, "medium": 1.0, "low": 0.7}.get(criticality, 1.0)

    # 4. Historical frequency
    historical_count = 0
    for h in historical:
        if h.get("cwe_id") == cwe_id:
            historical_count += h.get("count", 0)

    history_bonus = min(historical_count * 2, 20)  # Cap at 20

    # 5. Composite score
    # Key insight: team awareness WITHOUT remediation INCREASES risk
    # (unlike traditional scoring where "known" might lower severity)
    composite = (
        code_score
        + deferral_penalty  # Deferred work ADDS risk
        + history_bonus     # Repeated findings ADD risk
    ) * arch_multiplier     # Architecture MULTIPLIES risk

    composite = min(100, max(0, composite))

    # Generate explanation
    explanation_parts = [f"Code severity: {severity} ({code_score}/100)"]

    if deferral_penalty > 0:
        explanation_parts.append(
            f"DEFERRAL PENALTY: +{deferral_penalty} — team is aware but has not fixed this"
        )

    if history_bonus > 0:
        explanation_parts.append(
            f"Historical pattern: +{history_bonus} — {cwe_id} has appeared {historical_count} times before"
        )

    if arch_multiplier > 1.0:
        explanation_parts.append(
            f"Architecture: x{arch_multiplier} — {file_path} is in a {criticality}-criticality module"
        )

    if related_correlations:
        explanation_parts.append(
            f"Cross-source context: {len(related_correlations)} team discussions reference this issue"
        )

    return {
        "composite_score": round(composite, 1),
        "code_severity_score": code_score,
        "team_awareness_score": awareness_score,
        "deferral_penalty": deferral_penalty,
        "architectural_multiplier": arch_multiplier,
        "historical_frequency": historical_count,
        "related_correlations": len(related_correlations),
        "explanation": " | ".join(explanation_parts),
    }


def rank_findings_by_risk(findings: list, correlations: list,
                          historical: list, architecture: dict) -> list:
    """
    Re-rank findings by composite risk score instead of raw severity.

    This is the KEY DIFFERENTIATOR: a MEDIUM severity finding in a
    critical module with a deferred fix and historical pattern can
    rank HIGHER than a HIGH severity finding in test code with no
    team context. No code-only scanner can do this.
    """
    scored_findings = []
    for finding in findings:
        risk = compute_risk_score(finding, correlations, historical, architecture)
        finding["risk_score"] = risk
        scored_findings.append(finding)

    # Sort by composite score descending
    scored_findings.sort(key=lambda f: f.get("risk_score", {}).get("composite_score", 0), reverse=True)

    return scored_findings

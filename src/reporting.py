from __future__ import annotations

from collections import Counter

from .models import Finding


def portfolio_metrics(findings: list[Finding]) -> dict[str, object]:
    severities = Counter(f.severity for f in findings)
    return {
        "total_findings": len(findings),
        "critical_high": severities["Critical"] + severities["High"],
        "highest_score": max((f.score for f in findings), default=0),
        "by_severity": dict(sorted(severities.items())),
        "affected_users": len({f.user for f in findings}),
    }


def render_markdown(findings: list[Finding]) -> str:
    metrics = portfolio_metrics(findings)
    lines = [
        "# MFA Assurance Detection Assessment",
        "",
        "> Synthetic lab output. Findings are detection signals for investigation, not proof of MFA bypass or compromise.",
        "",
        "## Executive metrics",
        f"- Total findings: {metrics['total_findings']}",
        f"- Critical/High: {metrics['critical_high']}",
        f"- Highest score: {metrics['highest_score']}",
        f"- Affected users: {metrics['affected_users']}",
        "",
        "## Findings",
    ]
    for finding in findings:
        lines.extend([
            "",
            f"### {finding.title}",
            f"- Finding ID: `{finding.finding_id}`",
            f"- User: `{finding.user}`",
            f"- Severity / score: **{finding.severity} / {finding.score}**",
            f"- ATT&CK context: {', '.join(finding.mitre_techniques)}",
            f"- Evidence: {', '.join(finding.evidence_ids)}",
            f"- Rationale: {finding.rationale}",
            f"- Remediation: {finding.remediation}",
            f"- Validation: {finding.validation}",
        ])
    return "\n".join(lines) + "\n"

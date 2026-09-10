# Example MFA Assurance Assessment

> Synthetic demonstration output. Detection signals require analyst validation and do not prove account compromise or an MFA bypass.

## Executive summary

The synthetic dataset demonstrates two investigation scenarios: a high-risk successful sign-in where expected MFA/Conditional Access assurance was absent, and a short failure/interruption sequence followed by a successful authentication. The purpose is to show how identity telemetry can be converted into explainable, evidence-linked findings.

## Example findings

### Successful authentication with weakened MFA assurance
- Severity: Critical
- Example score: 100
- ATT&CK context: T1078
- Evidence: evt-001
- Analyst question: Was this access path intentionally excluded, or did policy assurance fail to apply?
- Remediation: Review Conditional Access targeting, authentication strength, device requirements, and active sessions.
- Validation: Re-test the same synthetic access pattern and verify the expected challenge/control is enforced.

### Authentication failure-to-success sequence requires review
- Severity: Medium/High depending on contextual risk
- ATT&CK context: T1078
- Evidence: evt-002, evt-003, evt-004
- Analyst question: Does the sequence represent expected retry/step-up behavior or anomalous session progression?
- Remediation: Validate user intent, challenge history, source context, and session state.
- Validation: Confirm expected policy behavior and alerting with controlled synthetic tests.

## Governance note

A detection is not considered remediated simply because the alert stops firing. Closure should include documented policy change where required, re-test evidence, and analyst validation that the intended authentication control now operates correctly.

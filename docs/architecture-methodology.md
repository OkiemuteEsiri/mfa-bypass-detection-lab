# Architecture and Methodology

## Purpose

This project is a defensive identity-detection lab for evaluating MFA assurance and authentication-policy telemetry. It does not attempt to defeat MFA. Instead, it identifies authentication events and sequences that warrant investigation because assurance controls may not have operated as intended.

## Architecture

1. **Input validation** — synthetic sign-in events are validated for timestamp quality, authentication result, MFA state, risk level, and required identity fields.
2. **Correlation** — events are grouped by user and evaluated as single-event conditions and short authentication sequences.
3. **Risk scoring** — findings receive a bounded 0–100 score using MFA assurance, Conditional Access application, provider risk, device trust, and sequence context.
4. **Evidence preservation** — every finding carries source event IDs and deterministic finding IDs.
5. **Reporting** — portfolio metrics and Markdown output support analyst triage and executive review.

## Detection controls

### Successful authentication with weakened assurance
Raises a finding when a successful sign-in has unsatisfied/not-required MFA. Risk increases when Conditional Access was not applied, the sign-in is high-risk, or the device is untrusted.

### Failure-to-success sequence
Correlates failed/interrupted authentication events followed by a success in a 20-minute window. This is an investigation signal only; legitimate retries and successful step-up authentication can produce similar patterns.

## MITRE ATT&CK context

- **T1078 — Valid Accounts**: identity compromise can result in successful access using legitimate accounts.

ATT&CK mappings provide threat context and are not evidence that compromise occurred.

## Remediation workflow

1. Confirm user intent and source context.
2. Review Conditional Access evaluation and exclusions.
3. Review authentication strength and registered methods.
4. Inspect session/token state and device trust.
5. Revoke sessions or reset credentials only when investigation supports that action.
6. Correct policy scope or authentication-strength gaps.
7. Re-test with synthetic identities.
8. Close only when expected policy enforcement and telemetry are demonstrated.

## Limitations

This lab uses synthetic telemetry and simplified scoring. Production identity platforms expose richer fields such as authentication details, token claims, sign-in risk reasons, session controls, and policy-result arrays. A production implementation should normalize provider-specific schemas and tune baselines for organizational context.

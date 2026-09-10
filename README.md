# MFA Assurance Detection Lab

Defensive identity-security project for detecting authentication events and sequences where MFA and Conditional Access assurance may not have operated as expected.

> This repository is intentionally defensive. It does **not** contain techniques for defeating MFA, stealing sessions, phishing credentials, or targeting live identity providers. All data is synthetic.

## Problem statement

Identity teams often have large sign-in datasets but limited context around whether a successful authentication met the intended security controls. A raw success event is not enough: analysts need to understand MFA state, Conditional Access application, device trust, provider risk, and the surrounding authentication sequence.

This lab converts synthetic authentication telemetry into evidence-linked findings that can be triaged, remediated, and re-tested.

## Architecture

```text
Synthetic auth telemetry
        |
        v
Validated event models
        |
        v
User/time correlation engine
        |
        v
Contextual 0-100 risk scoring
        |
        v
Evidence-linked findings
        |
        +--> Portfolio metrics
        +--> Markdown assessment
        +--> Remediation / validation workflow
```

## Implemented capabilities

- immutable authentication and finding models
- timezone-aware UTC normalization
- fail-closed validation of authentication state and risk fields
- deterministic finding identifiers
- per-user chronological correlation
- detection of successful access with weakened MFA assurance
- detection of authentication failure/interruption-to-success sequences
- contextual scoring using:
  - MFA state
  - Conditional Access application
  - identity-provider risk
  - device trust
  - sequence context
- severity classification from bounded 0–100 scores
- evidence preservation through event IDs
- portfolio metrics by severity and affected users
- Markdown assessment reporting
- realistic synthetic sign-in telemetry
- unit-test coverage for validation, clean authentication, risky authentication, correlation, deterministic IDs, metrics, and reporting
- least-privilege GitHub Actions CI

## Repository structure

```text
.
├── .github/workflows/ci.yml
├── data/
│   └── synthetic_auth_events.json
├── docs/
│   └── architecture-methodology.md
├── reports/
│   └── example-assessment.md
├── src/
│   ├── detector.py
│   ├── io.py
│   ├── models.py
│   └── reporting.py
└── tests/
    └── test_detector.py
```

## Detection logic

### 1. Successful authentication with weakened MFA assurance

A successful sign-in is investigated when MFA is recorded as `not_satisfied` or `not_required`. Risk increases when:

- Conditional Access was not applied
- the identity provider marks the sign-in high-risk
- the device is untrusted

The result is an investigation signal, not a declaration that MFA was bypassed.

### 2. Authentication failure-to-success sequence

The engine looks for failed or interrupted authentication events followed by a success within a short time window. This can expose suspicious authentication progression, but it can also represent legitimate retry or step-up behavior, so analyst validation is mandatory.

## MITRE ATT&CK

- **T1078 — Valid Accounts**

ATT&CK mappings are used as threat context only. They do not prove compromise.

## Example usage

```python
from src.io import load_events
from src.detector import detect
from src.reporting import render_markdown

events = load_events("data/synthetic_auth_events.json")
findings = detect(events)
print(render_markdown(findings))
```

## Risk model

The scoring model is deliberately explainable rather than opaque. Individual risk factors add bounded weight to a 0–100 score:

- successful authentication without satisfied MFA
- missing Conditional Access enforcement
- high provider risk
- untrusted device context
- correlated authentication sequence

Severity bands:

- 85–100: Critical
- 70–84: High
- 45–69: Medium
- below 45: Low

The score is a prioritization aid, not a probability of compromise.

## Remediation and validation

A finding should not be closed just because an alert stops firing. The workflow is:

1. validate user intent and source context
2. review Conditional Access policy evaluation and exclusions
3. review authentication strength and registered methods
4. inspect device and session context
5. revoke sessions or reset credentials only when investigation supports it
6. correct policy scope or assurance gaps
7. re-test with synthetic identities
8. retain evidence demonstrating expected enforcement and telemetry

## Testing

The repository contains unit tests covering:

- UTC normalization
- invalid MFA-state rejection
- strong-authentication negative case
- weakened-assurance positive detection
- sequence correlation
- deterministic finding IDs
- bounded portfolio metrics
- reporting caveats

Run locally with:

```bash
python -m unittest discover -s tests -v
```

## Skills demonstrated

This project demonstrates practical capability in:

- Identity Detection Engineering
- MFA assurance analysis
- Conditional Access review
- authentication telemetry normalization
- security event correlation
- explainable risk scoring
- evidence-driven incident triage
- MITRE ATT&CK contextual mapping
- remediation validation
- Python security engineering
- unit testing
- GitHub Actions security hygiene

## Limitations

This is a synthetic lab and intentionally simplifies production identity schemas. A production implementation would normally ingest richer fields such as authentication details, token/session information, Conditional Access result arrays, identity-protection risk reasons, managed-device state, and provider-specific policy metadata.

The project does not make automated compromise decisions and does not perform production enforcement actions.

## Roadmap

- provider adapters for normalized Entra/Okta-style synthetic schemas
- impossible-travel context using precomputed synthetic geolocation data
- known-device baselines
- authentication-method-strength policy evaluation
- risk trend reporting
- suppression and exception governance
- JSON report export
- Sigma/KQL equivalents for defensive detections

## Safety

All identities, domains, addresses, and events are synthetic. Reserved documentation IP ranges and `.invalid` domains are used. No employer/client telemetry, credentials, live identity systems, phishing infrastructure, session theft, or offensive MFA-abuse techniques are included.

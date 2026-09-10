from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import timedelta
from typing import Iterable

from .models import AuthEvent, Finding, parse_utc

SEVERITY_BY_SCORE = ((85, "Critical"), (70, "High"), (45, "Medium"), (0, "Low"))


def _finding_id(kind: str, user: str, evidence: Iterable[str]) -> str:
    material = "|".join([kind, user, *sorted(evidence)])
    return hashlib.sha256(material.encode()).hexdigest()[:16]


def _severity(score: int) -> str:
    for threshold, label in SEVERITY_BY_SCORE:
        if score >= threshold:
            return label
    return "Low"


def detect(events: list[AuthEvent]) -> list[Finding]:
    findings: list[Finding] = []
    by_user: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        by_user[event.user].append(event)

    for user, user_events in by_user.items():
        user_events.sort(key=lambda e: parse_utc(e.timestamp))

        for event in user_events:
            score = 0
            reasons: list[str] = []
            techniques = ["T1078"]

            if event.result == "success" and event.mfa_state in {"not_satisfied", "not_required"}:
                score += 45
                reasons.append("successful sign-in without satisfied MFA")
            if event.result == "success" and not event.conditional_access_applied:
                score += 20
                reasons.append("conditional access was not applied")
            if event.result == "success" and event.risk_level == "high":
                score += 25
                reasons.append("identity provider marked sign-in high risk")
            if event.result == "success" and not event.device_trust:
                score += 10
                reasons.append("device was not trusted")

            score = min(score, 100)
            if score >= 45:
                findings.append(
                    Finding(
                        finding_id=_finding_id("mfa-gap", user, [event.event_id]),
                        title="Successful authentication with weakened MFA assurance",
                        severity=_severity(score),
                        score=score,
                        user=user,
                        evidence_ids=(event.event_id,),
                        mitre_techniques=tuple(techniques),
                        rationale="; ".join(reasons),
                        remediation="Review Conditional Access scope, authentication strength, exclusions, and device requirements; revoke suspicious sessions where appropriate.",
                        validation="Re-test with a synthetic user and confirm the same access path is blocked or requires the intended MFA/authentication strength.",
                    )
                )

        for idx, event in enumerate(user_events):
            if event.result != "failure" or event.mfa_state == "satisfied":
                continue
            start = parse_utc(event.timestamp)
            window = [
                e for e in user_events[idx:]
                if parse_utc(e.timestamp) - start <= timedelta(minutes=20)
            ]
            successes = [e for e in window if e.result == "success"]
            if successes and len(window) >= 3:
                evidence = [e.event_id for e in window]
                score = min(65 + (10 if any(e.risk_level == "high" for e in window) else 0), 100)
                findings.append(
                    Finding(
                        finding_id=_finding_id("failure-success-sequence", user, evidence),
                        title="Authentication failure-to-success sequence requires review",
                        severity=_severity(score),
                        score=score,
                        user=user,
                        evidence_ids=tuple(evidence),
                        mitre_techniques=("T1078",),
                        rationale="Multiple failed/interrupted authentication events were followed by a success within 20 minutes.",
                        remediation="Validate user intent, source context, session state, and MFA challenge history; reset sessions if unauthorized activity is suspected.",
                        validation="Confirm subsequent synthetic challenge sequences generate expected telemetry and policy enforcement without false closure.",
                    )
                )
                break

    unique = {f.finding_id: f for f in findings}
    return sorted(unique.values(), key=lambda f: (-f.score, f.finding_id))

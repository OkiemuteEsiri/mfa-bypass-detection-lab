from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

VALID_RESULTS = {"success", "failure", "interrupted"}
VALID_MFA = {"satisfied", "not_satisfied", "not_required", "unknown"}
VALID_RISK = {"low", "medium", "high", "unknown"}


def parse_utc(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class AuthEvent:
    event_id: str
    timestamp: str
    user: str
    source_ip: str
    result: str
    mfa_state: str
    auth_method: str
    device_trust: bool
    conditional_access_applied: bool
    risk_level: str
    country: str
    app: str

    def __post_init__(self) -> None:
        parse_utc(self.timestamp)
        if self.result not in VALID_RESULTS:
            raise ValueError(f"invalid result: {self.result}")
        if self.mfa_state not in VALID_MFA:
            raise ValueError(f"invalid mfa_state: {self.mfa_state}")
        if self.risk_level not in VALID_RISK:
            raise ValueError(f"invalid risk_level: {self.risk_level}")
        if not self.event_id or not self.user or not self.source_ip:
            raise ValueError("event_id, user and source_ip are required")


@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    severity: str
    score: int
    user: str
    evidence_ids: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    rationale: str
    remediation: str
    validation: str

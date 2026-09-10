from __future__ import annotations

import json
from pathlib import Path

from .models import AuthEvent


def load_events(path: str | Path) -> list[AuthEvent]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("input must be a JSON array")
    events = [AuthEvent(**item) for item in payload]
    ids = [event.event_id for event in events]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate event_id detected")
    return events

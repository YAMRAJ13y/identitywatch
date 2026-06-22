"""Load authentication events from JSONL, JSON, or CSV.

Expected fields per record: timestamp (ISO-8601), user, ip, event_type, and
optionally country, city, lat, lon, asn, user_agent, session_id.
"""
from __future__ import annotations

import csv
import json
from datetime import datetime

from .models import AuthEvent


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))


def _to_float(value) -> float | None:
    if value in (None, "", "null"):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _record_to_event(d: dict) -> AuthEvent:
    return AuthEvent(
        timestamp=_parse_ts(d["timestamp"]),
        user=str(d.get("user", "")),
        ip=str(d.get("ip", "")),
        event_type=str(d.get("event_type", "")),
        country=str(d.get("country", "")),
        city=str(d.get("city", "")),
        lat=_to_float(d.get("lat")),
        lon=_to_float(d.get("lon")),
        asn=str(d.get("asn", "")),
        user_agent=str(d.get("user_agent", "")),
        session_id=str(d.get("session_id", "")),
    )


def load_events(path: str) -> list[AuthEvent]:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()

    events: list[AuthEvent] = []
    low = path.lower()
    if low.endswith((".jsonl", ".ndjson")):
        for line in text.splitlines():
            line = line.strip()
            if line:
                events.append(_record_to_event(json.loads(line)))
    elif low.endswith(".json"):
        for d in json.loads(text):
            events.append(_record_to_event(d))
    else:  # CSV
        for d in csv.DictReader(text.splitlines()):
            events.append(_record_to_event(d))

    events.sort(key=lambda e: e.timestamp)
    return events

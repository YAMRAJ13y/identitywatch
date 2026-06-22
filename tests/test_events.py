"""Auth-log loading."""
from __future__ import annotations

import pathlib

from identitywatch.events import load_events

SAMPLE = pathlib.Path(__file__).resolve().parent.parent / "examples" / "sample_auth_log.jsonl"


def test_loads_and_sorts():
    events = load_events(str(SAMPLE))
    assert len(events) == 30
    assert events == sorted(events, key=lambda e: e.timestamp)


def test_field_parsing():
    events = load_events(str(SAMPLE))
    alice = next(e for e in events if e.user == "alice")
    assert alice.country == "US"
    assert alice.lat is not None
    assert alice.event_type == "login_success"

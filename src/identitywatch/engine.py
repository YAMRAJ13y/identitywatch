"""Run every detection rule over an auth-log and assemble a Report."""
from __future__ import annotations

from .events import load_events
from .llm import narrate
from .models import SEVERITY_RANK, Report
from .rules import RULES


def scan(path: str, use_llm: bool = False) -> Report:
    events = load_events(path)
    alerts = []
    for rule in RULES:
        alerts.extend(rule(events))
    alerts.sort(key=lambda a: (-SEVERITY_RANK.get(a.severity, 0), a.timestamp))

    if use_llm:
        narrate(alerts)

    return Report(
        alerts=alerts,
        events_count=len(events),
        users_count=len({e.user for e in events}),
        rules_run=len(RULES),
        source=path,
    )

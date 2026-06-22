"""Each detection must fire on the planted attacks and stay quiet on benign traffic."""
from __future__ import annotations

import pathlib
from datetime import datetime, timedelta, timezone

from identitywatch import scan
from identitywatch.models import AuthEvent
from identitywatch.rules import RULES

SAMPLE = pathlib.Path(__file__).resolve().parent.parent / "examples" / "sample_auth_log.jsonl"
BASE = datetime(2026, 6, 20, 9, 0, tzinfo=timezone.utc)


def _rule_ids(report):
    return {a.rule_id for a in report.alerts}


def test_all_detections_fire_on_sample():
    report = scan(str(SAMPLE))
    got = _rule_ids(report)
    for rid in ("IW001", "IW002", "IW003", "IW004", "IW005", "IW006"):
        assert rid in got, (rid, sorted(got))


def test_severities():
    report = scan(str(SAMPLE))
    by_id = {a.rule_id: a for a in report.alerts}
    assert by_id["IW001"].severity == "high"  # impossible travel
    assert by_id["IW006"].severity == "high"  # session reuse
    assert by_id["IW005"].severity == "medium"  # new-country


def test_attack_mapping_present():
    report = scan(str(SAMPLE))
    travel = next(a for a in report.alerts if a.rule_id == "IW001")
    assert travel.attack.technique == "T1078"
    mfa = next(a for a in report.alerts if a.rule_id == "IW002")
    assert mfa.attack.technique == "T1621"


def _evt(user, ip, etype, mins, **kw):
    return AuthEvent(timestamp=BASE + timedelta(minutes=mins), user=user, ip=ip, event_type=etype, **kw)


def test_no_false_positives_on_benign_traffic():
    benign = [
        _evt("x", "198.51.100.5", "login_success", 0, country="US", city="Denver", lat=39.74, lon=-104.99, session_id="s1"),
        _evt("x", "198.51.100.5", "login_success", 180, country="US", city="Denver", lat=39.74, lon=-104.99, session_id="s1"),
        _evt("y", "198.51.100.9", "login_failure", 5),
        _evt("y", "198.51.100.9", "login_failure", 6),
        _evt("z", "198.51.100.7", "mfa_challenge", 10),
        _evt("z", "198.51.100.7", "mfa_approved", 11),
    ]
    for rule in RULES:
        assert rule(benign) == [], rule.__name__

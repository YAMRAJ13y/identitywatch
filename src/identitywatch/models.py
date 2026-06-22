"""Core data models for IdentityWatch."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


@dataclass
class AuthEvent:
    """One authentication-log event (sign-in, failure, MFA prompt, token use)."""

    timestamp: datetime
    user: str
    ip: str
    event_type: str  # login_success/failure, mfa_challenge/denied/approved, token_use
    country: str = ""
    city: str = ""
    lat: float | None = None
    lon: float | None = None
    asn: str = ""
    user_agent: str = ""
    session_id: str = ""


@dataclass
class Attack:
    technique: str  # e.g. "T1078"
    name: str
    tactic: str  # e.g. "TA0001"


@dataclass
class Alert:
    rule_id: str
    rule_name: str
    severity: str  # high | medium | low
    user: str
    attack: Attack
    description: str
    evidence: list[str] = field(default_factory=list)
    timestamp: str = ""
    recommendation: str = ""
    narrative: str | None = None  # optional Claude-written triage narrative


@dataclass
class Report:
    alerts: list[Alert] = field(default_factory=list)
    events_count: int = 0
    users_count: int = 0
    rules_run: int = 0
    source: str = ""

    def severity_summary(self) -> dict:
        out = {"high": 0, "medium": 0, "low": 0}
        for a in self.alerts:
            out[a.severity] = out.get(a.severity, 0) + 1
        return out

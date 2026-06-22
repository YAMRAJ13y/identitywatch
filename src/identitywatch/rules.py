"""Detection-as-code: identity-attack rules, each mapped to MITRE ATT&CK.

Every rule is a function ``detect(events) -> list[Alert]`` registered in ``RULES``.
Adding a detection is just writing a function and appending it — the engine, report,
and tests pick it up automatically.
"""
from __future__ import annotations

import math
from collections import defaultdict
from datetime import timedelta

from .models import Alert, Attack, AuthEvent

_IMPOSSIBLE_SPEED_KMH = 900.0  # faster than a commercial flight
_MIN_TRAVEL_KM = 500.0


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlam / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def _by_user(events: list[AuthEvent]) -> dict[str, list[AuthEvent]]:
    out: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in events:
        out[e.user].append(e)
    return out


def _window(events: list[AuthEvent], anchor, minutes: int) -> list[AuthEvent]:
    return [e for e in events if 0 <= (e.timestamp - anchor.timestamp).total_seconds() <= minutes * 60]


def detect_impossible_travel(events: list[AuthEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    for user, evs in _by_user(events).items():
        logins = sorted(
            (e for e in evs if e.event_type == "login_success" and e.lat is not None),
            key=lambda e: e.timestamp,
        )
        for a, b in zip(logins, logins[1:]):
            dist = _haversine_km(a.lat, a.lon, b.lat, b.lon)
            hours = (b.timestamp - a.timestamp).total_seconds() / 3600
            if dist < _MIN_TRAVEL_KM or hours < 0:
                continue
            speed = dist / hours if hours > 0 else float("inf")
            if speed > _IMPOSSIBLE_SPEED_KMH:
                speed_txt = "∞" if speed == float("inf") else f"{int(speed)}"
                alerts.append(Alert(
                    "IW001", "Impossible travel", "high", user,
                    Attack("T1078", "Valid Accounts", "TA0001"),
                    f"{user} signed in from {a.city or a.country} then {b.city or b.country} "
                    f"(~{int(dist)} km apart) within {hours:.1f}h ({speed_txt} km/h).",
                    evidence=[
                        f"{a.timestamp.isoformat()} {a.ip} {a.city},{a.country}",
                        f"{b.timestamp.isoformat()} {b.ip} {b.city},{b.country}",
                    ],
                    timestamp=b.timestamp.isoformat(),
                    recommendation="Revoke active sessions, force re-auth, and confirm with the user.",
                ))
    return alerts


def detect_mfa_fatigue(events: list[AuthEvent], window_min: int = 10, threshold: int = 5) -> list[Alert]:
    alerts: list[Alert] = []
    for user, evs in _by_user(events).items():
        prompts = sorted(
            (e for e in evs if e.event_type in ("mfa_challenge", "mfa_denied")),
            key=lambda e: e.timestamp,
        )
        for anchor in prompts:
            burst = _window(prompts, anchor, window_min)
            if len(burst) < threshold:
                continue
            approved = any(
                e.event_type == "mfa_approved"
                and anchor.timestamp <= e.timestamp <= burst[-1].timestamp + timedelta(minutes=5)
                for e in evs
            )
            severity = "high" if approved else "medium"
            tail = (" and one was then approved — likely fatigue compromise."
                    if approved else " (possible MFA bombing).")
            alerts.append(Alert(
                "IW002", "MFA fatigue / bombing", severity, user,
                Attack("T1621", "Multi-Factor Authentication Request Generation", "TA0001"),
                f"{user} received {len(burst)} MFA prompts within {window_min} min" + tail,
                evidence=[f"{e.timestamp.isoformat()} {e.event_type} {e.ip}" for e in burst[:6]],
                timestamp=anchor.timestamp.isoformat(),
                recommendation="Enforce number-matching MFA, investigate the source, and reset credentials.",
            ))
            break  # one alert per user
    return alerts


def detect_password_spray(events: list[AuthEvent], window_min: int = 15, min_users: int = 5) -> list[Alert]:
    alerts: list[Alert] = []
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in events:
        if e.event_type == "login_failure":
            by_ip[e.ip].append(e)
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e.timestamp)
        for anchor in evs:
            burst = _window(evs, anchor, window_min)
            users = sorted({e.user for e in burst})
            if len(users) >= min_users:
                alerts.append(Alert(
                    "IW003", "Password spraying", "high", "(multiple users)",
                    Attack("T1110.003", "Brute Force: Password Spraying", "TA0006"),
                    f"IP {ip} attempted logins against {len(users)} distinct users within {window_min} min.",
                    evidence=[f"{ip} -> {users[:8]}"],
                    timestamp=anchor.timestamp.isoformat(),
                    recommendation="Block/rate-limit the source IP, enforce MFA, and check for any successes.",
                ))
                break
    return alerts


def detect_brute_force(events: list[AuthEvent], window_min: int = 10, threshold: int = 6) -> list[Alert]:
    alerts: list[Alert] = []
    for user, evs in _by_user(events).items():
        evs.sort(key=lambda e: e.timestamp)
        fails = [e for e in evs if e.event_type == "login_failure"]
        for anchor in fails:
            burst = _window(fails, anchor, window_min)
            if len(burst) < threshold:
                continue
            last = burst[-1].timestamp
            success = any(
                e.event_type == "login_success" and last <= e.timestamp <= last + timedelta(minutes=10)
                for e in evs
            )
            severity = "high" if success else "medium"
            tail = (" followed by a success — likely account takeover."
                    if success else " (brute-force attempt).")
            alerts.append(Alert(
                "IW004", "Brute force / credential stuffing", severity, user,
                Attack("T1110", "Brute Force", "TA0006"),
                f"{user} had {len(burst)} failed logins within {window_min} min" + tail,
                evidence=[f"{e.timestamp.isoformat()} fail {e.ip}" for e in burst[:6]],
                timestamp=anchor.timestamp.isoformat(),
                recommendation="Lock the account, force a reset, and review the successful session if any.",
            ))
            break
    return alerts


def detect_new_country(events: list[AuthEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    seen: dict[str, set[str]] = defaultdict(set)
    for e in sorted(events, key=lambda e: e.timestamp):
        if e.event_type != "login_success" or not e.country:
            continue
        if seen[e.user] and e.country not in seen[e.user]:
            alerts.append(Alert(
                "IW005", "New-country sign-in", "medium", e.user,
                Attack("T1078", "Valid Accounts", "TA0001"),
                f"{e.user} signed in from a new country ({e.country}); "
                f"previously only seen from {sorted(seen[e.user])}.",
                evidence=[f"{e.timestamp.isoformat()} {e.ip} {e.city},{e.country}"],
                timestamp=e.timestamp.isoformat(),
                recommendation="Verify with the user; correlate with impossible-travel and token-theft signals.",
            ))
        seen[e.user].add(e.country)
    return alerts


def detect_session_reuse(events: list[AuthEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    by_sid: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in events:
        if e.session_id and e.event_type in ("login_success", "token_use"):
            by_sid[e.session_id].append(e)
    for sid, evs in by_sid.items():
        ips = {e.ip for e in evs}
        countries = {e.country for e in evs if e.country}
        if len(ips) > 1 and len(countries) > 1:
            evs.sort(key=lambda e: e.timestamp)
            alerts.append(Alert(
                "IW006", "Session token reuse", "high", evs[0].user,
                Attack("T1539", "Steal Web Session Cookie", "TA0006"),
                f"Session {sid} for {evs[0].user} was used from {len(ips)} IPs across "
                f"{sorted(countries)} — likely a stolen session cookie.",
                evidence=[f"{e.timestamp.isoformat()} {e.ip} {e.country}" for e in evs[:6]],
                timestamp=evs[-1].timestamp.isoformat(),
                recommendation="Revoke the session, rotate cookies/secrets, and investigate token theft.",
            ))
    return alerts


RULES = [
    detect_impossible_travel,
    detect_mfa_fatigue,
    detect_password_spray,
    detect_brute_force,
    detect_new_country,
    detect_session_reuse,
]

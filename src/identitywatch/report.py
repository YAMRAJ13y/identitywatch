"""Render an IdentityWatch Report to JSON and markdown."""
from __future__ import annotations

from .models import SEVERITY_RANK, Report

_ICON = {"high": "🔴", "medium": "🟠", "low": "🟡"}


def to_dict(report: Report) -> dict:
    return {
        "source": report.source,
        "events_count": report.events_count,
        "users_count": report.users_count,
        "rules_run": report.rules_run,
        "severity_summary": report.severity_summary(),
        "alerts_count": len(report.alerts),
        "alerts": [
            {
                "rule_id": a.rule_id,
                "rule_name": a.rule_name,
                "severity": a.severity,
                "user": a.user,
                "timestamp": a.timestamp,
                "attack": {
                    "technique": a.attack.technique,
                    "name": a.attack.name,
                    "tactic": a.attack.tactic,
                },
                "description": a.description,
                "evidence": a.evidence,
                "recommendation": a.recommendation,
                "narrative": a.narrative,
            }
            for a in report.alerts
        ],
    }


def to_markdown(report: Report) -> str:
    s = report.severity_summary()
    lines = [
        "# IdentityWatch — Alert Report",
        "",
        f"**Source:** `{report.source}`  ·  **Events:** {report.events_count}  ·  "
        f"**Users:** {report.users_count}  ·  **Rules:** {report.rules_run}",
        f"**Alerts:** {len(report.alerts)} — "
        f"🔴 {s['high']} high · 🟠 {s['medium']} medium · 🟡 {s['low']} low",
        "",
    ]
    if not report.alerts:
        lines += ["✅ No identity-attack patterns detected.", ""]
        return "\n".join(lines)

    ordered = sorted(report.alerts, key=lambda x: (-SEVERITY_RANK.get(x.severity, 0), x.timestamp))
    for a in ordered:
        icon = _ICON.get(a.severity, "•")
        lines += [
            f"### {icon} `{a.rule_id}` {a.rule_name} — {a.severity.upper()}  ·  user: `{a.user}`",
            f"- **What:** {a.description}",
            f"- **ATT&CK:** {a.attack.technique} {a.attack.name} ({a.attack.tactic})",
            f"- **When:** {a.timestamp}",
        ]
        for ev in a.evidence:
            lines.append(f"  - `{ev}`")
        lines.append(f"- **Recommend:** {a.recommendation}")
        if a.narrative:
            lines.append(f"- **Triage:** {a.narrative}")
        lines.append("")
    return "\n".join(lines)

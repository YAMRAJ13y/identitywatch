"""Optional Claude triage narratives for alerts.

Runs only when ``anthropic`` is installed and ``ANTHROPIC_API_KEY`` is set; the
detections and report work fully offline without it.
"""
from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Alert

_SYSTEM = (
    "You are a SOC analyst. Given one identity-attack alert, write a single concise "
    "sentence a tier-1 analyst could paste into a ticket: what likely happened and the "
    "first response step. Be specific, no preamble, no markdown."
)


def narrate(alerts: list[Alert], model: str | None = None) -> None:
    try:
        from anthropic import Anthropic
    except Exception:
        return
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return

    client = Anthropic()
    model = model or os.environ.get("IDENTITYWATCH_MODEL", "claude-haiku-4-5")
    for a in alerts:
        prompt = (
            f"Alert {a.rule_id} ({a.rule_name}), severity {a.severity}, user {a.user}.\n"
            f"ATT&CK {a.attack.technique} {a.attack.name}.\n"
            f"Detail: {a.description}\nEvidence: {'; '.join(a.evidence)}"
        )
        try:
            msg = client.messages.create(
                model=model, max_tokens=120, system=_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
            text = "".join(
                b.text for b in msg.content if getattr(b, "type", None) == "text"
            ).strip()
            if text:
                a.narrative = text
        except Exception:
            continue

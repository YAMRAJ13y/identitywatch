"""IdentityWatch - detection-as-code for identity-first attacks.

Scans authentication logs for the 2026 identity threats that dominate breaches —
impossible travel, MFA fatigue/bombing, password spraying, brute force, new-country
sign-ins, and stolen session cookies — and emits alerts mapped to MITRE ATT&CK.
Runs offline on a bundled sample log; an optional Claude layer adds triage narratives.

Public API:
    scan(path, use_llm=False) -> Report
    to_dict(report) / to_markdown(report)
    RULES (the detection-as-code ruleset) in identitywatch.rules
"""
from __future__ import annotations

from .engine import scan
from .models import Alert, AuthEvent, Report
from .report import to_dict, to_markdown

__version__ = "0.1.0"

__all__ = ["scan", "Report", "Alert", "AuthEvent", "to_dict", "to_markdown", "__version__"]

"""Report serialization."""
from __future__ import annotations

import json
import pathlib

from identitywatch import scan, to_dict, to_markdown

SAMPLE = pathlib.Path(__file__).resolve().parent.parent / "examples" / "sample_auth_log.jsonl"


def test_to_dict_round_trips():
    report = scan(str(SAMPLE))
    d = to_dict(report)
    assert d["alerts_count"] == len(report.alerts)
    assert d["severity_summary"]["high"] >= 4
    assert d["alerts"][0]["attack"]["technique"]
    json.loads(json.dumps(d))


def test_to_markdown():
    report = scan(str(SAMPLE))
    md = to_markdown(report)
    assert "# IdentityWatch" in md
    assert "ATT&CK" in md

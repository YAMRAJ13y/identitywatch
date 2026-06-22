"""IdentityWatch command-line interface.

    identitywatch scan <auth_log.jsonl> [--json] [--llm] [--fail-on high|medium|any|never]
    identitywatch version
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .engine import scan
from .models import SEVERITY_RANK
from .report import to_dict, to_markdown

_FAIL_THRESHOLD = {"any": 1, "medium": 2, "high": 3, "never": 99}


def _run_scan(args) -> int:
    try:
        report = scan(args.path, use_llm=args.llm)
    except FileNotFoundError:
        print(f"error: auth-log not found: {args.path}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(to_dict(report), indent=2, ensure_ascii=False))
    else:
        print(to_markdown(report))

    worst = max([SEVERITY_RANK[a.severity] for a in report.alerts] + [0])
    return 1 if worst >= _FAIL_THRESHOLD[args.fail_on] else 0


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        prog="identitywatch",
        description="Detection-as-code for identity attacks (impossible travel, MFA fatigue, "
        "password spraying, session theft) mapped to MITRE ATT&CK.",
    )
    sub = parser.add_subparsers(dest="cmd")

    sc = sub.add_parser("scan", help="scan an authentication log for identity attacks")
    sc.add_argument("path", help="path to an auth log (.jsonl / .json / .csv)")
    sc.add_argument("--json", action="store_true", help="emit JSON instead of markdown")
    sc.add_argument("--llm", action="store_true", help="add Claude triage narratives")
    sc.add_argument(
        "--fail-on",
        choices=list(_FAIL_THRESHOLD),
        default="high",
        help="exit non-zero when an alert at/above this severity exists (default: high)",
    )

    sub.add_parser("version", help="print the version")

    args = parser.parse_args(argv)
    if args.cmd == "scan":
        return _run_scan(args)
    if args.cmd == "version":
        print(__version__)
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

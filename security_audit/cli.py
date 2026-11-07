from __future__ import annotations

import argparse
from pathlib import Path

from security_audit.runner import run_audit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="security_audit",
        description="Run the local security audit and write a redacted daily report.",
    )
    parser.add_argument("--root", default=".", help="Repository root to scan")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip networked scanners such as npm audit and OSV",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="Exit 1 when an alert-level finding exists and skip desktop notification",
    )
    parser.add_argument("--no-notify", action="store_true", help="Do not send a desktop notification")
    args = parser.parse_args(argv)
    result = run_audit(
        Path(args.root),
        offline=args.offline,
        notify=not (args.no_notify or args.ci),
    )
    print(result.summary_line)
    if result.alert:
        return 1
    return 0

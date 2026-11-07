from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from security_audit.models import Finding

MARKER = "<!-- security-audit:generated -->"


def desktop_notification(count: int) -> str:
    if shutil.which("notify-send") is None:
        return "desktop notification unavailable"
    message = f"{count} critical security finding(s). See ALERT.md in the repository."
    try:
        subprocess.run(
            ["notify-send", "Security audit", message],
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "desktop notification unavailable"
    return "desktop notification sent"


def write_alerts(
    root: Path,
    findings: list[Finding],
    stamp: str,
    started_at: str,
    *,
    notify: bool,
) -> str:
    history = root / "alerts" / "history"
    history.mkdir(parents=True, exist_ok=True)
    alerts = [finding for finding in findings if finding.alert]
    lines = [
        MARKER,
        "",
        f"# Alert history {stamp}",
        "",
        f"Started: {started_at}",
        "",
        "Alert policy: environmental severity critical, and exposure in application, "
        "production-runtime, secret, database, or ci. Development-tooling advisories stay in the daily report.",
        "",
    ]
    notification = "not requested"
    if alerts:
        lines.append(f"Alert raised for {len(alerts)} finding(s).")
        for finding in alerts:
            lines.append(f"- {finding.severity}: {finding.title} ({finding.location})")
        alert_body = "\n".join(
            [
                MARKER,
                "",
                "# Security alert",
                "",
                f"{len(alerts)} critical finding(s) need review.",
                "",
                "Values are omitted. Open the daily report for location, impact, and the recommended change.",
                "",
                *[f"- {finding.title} — {finding.location}" for finding in alerts],
                "",
            ]
        )
        (root / "ALERT.md").write_text(alert_body, encoding="utf-8")
        if notify:
            notification = desktop_notification(len(alerts))
    else:
        lines.append("No alert was raised.")
        existing = root / "ALERT.md"
        if existing.is_file() and MARKER in existing.read_text(encoding="utf-8"):
            existing.unlink()
        notification = "not sent"
    lines.append("")
    lines.append(f"Desktop notification: {notification}")
    lines.append("")
    (history / f"{stamp}.md").write_text("\n".join(lines), encoding="utf-8")
    return notification

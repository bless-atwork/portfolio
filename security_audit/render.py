from __future__ import annotations

import json
from typing import Iterable

from security_audit.models import SEVERITIES, Finding, severity_rank
from security_audit.scanners.secrets import compiled_patterns
from security_audit.textutil import clean_text, redact

_PATTERNS = None


def _safe(value: object, limit: int = 400) -> str:
    global _PATTERNS
    if _PATTERNS is None:
        _PATTERNS = compiled_patterns()
    return clean_text(redact(str(value if value is not None else ""), _PATTERNS), limit)


def _bullets(findings: Iterable[Finding]) -> list[str]:
    lines: list[str] = []
    for finding in findings:
        lines.append(
            f"- **{_safe(finding.title, 180)}** ({finding.severity}, likelihood {finding.likelihood_score}/5, "
            f"impact {finding.impact_score}/5)"
        )
        lines.append(f"  - Location: `{_safe(finding.location, 180)}`")
        lines.append(f"  - Exposure: {_safe(finding.exposure, 60)}")
        lines.append(f"  - {_safe(finding.summary, 320)}")
        lines.append(f"  - Fix: {_safe(finding.recommendation, 320)}")
    return lines


def _section(title: str, body: list[str]) -> list[str]:
    lines = [f"# {title}", ""]
    lines.extend(body or ["None.", ""])
    if body and (not body[-1] or body[-1] != ""):
        lines.append("")
    elif not body:
        lines.append("")
    return lines


def render_markdown(payload: dict[str, object]) -> str:
    findings = payload["findings"]
    assert isinstance(findings, list)
    typed = [item for item in findings if isinstance(item, Finding)]
    scores = payload["scores"]
    assert isinstance(scores, dict)
    inventory = payload["inventory"]
    assert isinstance(inventory, dict)
    databases = payload["databases"]
    assert isinstance(databases, list)
    comparison = payload["comparison"]
    assert isinstance(comparison, dict)
    tools = payload["tools"]
    assert isinstance(tools, dict)

    by_severity = {severity: [] for severity in SEVERITIES}
    for finding in typed:
        if finding.category == "dependency":
            continue
        by_severity[finding.severity].append(finding)
    secrets = [finding for finding in typed if finding.category == "secret" or finding.exposure == "secret"]
    dependencies = [finding for finding in typed if finding.category == "dependency"]
    dependencies.sort(key=lambda item: (-severity_rank(item.severity), item.title))

    repos = inventory.get("repositories")
    repo_bits = []
    if isinstance(repos, list):
        for repo in repos:
            if not isinstance(repo, dict):
                continue
            languages = ", ".join(str(item) for item in repo.get("languages", [])) or "none detected"
            frameworks = ", ".join(str(item) for item in repo.get("frameworks", [])) or "none detected"
            repo_bits.append(
                f"{repo.get('name')} — languages: {languages}; frameworks: {frameworks}."
            )
    machine = inventory.get("machine_git") if isinstance(inventory.get("machine_git"), dict) else {}
    counts = machine.get("counts") if isinstance(machine, dict) else {}
    tool_bits = []
    for name, info in tools.items():
        if not isinstance(info, dict):
            continue
        state = "available" if info.get("available") else "not installed"
        if info.get("invoked"):
            state += ", invoked"
        reason = info.get("reason")
        if reason:
            state += f" ({reason})"
        tool_bits.append(f"{name}: {state}")

    executive = [
        (
            f"Security posture is **{scores['posture']}/100** and risk is **{scores['risk']}/100**. "
            "A higher posture is better. A higher risk means more weighted findings."
        ),
        "",
        f"Run window: {payload['started_at']} to {payload['finished_at']} ({payload['duration_seconds']} seconds).",
        "",
        "Repositories scanned:",
        *[f"- {bit}" for bit in repo_bits],
        "",
        (
            "Other git checkouts on this machine were counted and not read: "
            f"editor cache {counts.get('editor_plugin_cache', 0)}, "
            f"runtime managers {counts.get('runtime_manager', 0)}, "
            f"other {counts.get('other', 0)}. "
            "Their paths and contents are not copied into this report."
        ),
        "",
        "Scanners: " + "; ".join(tool_bits) + ".",
        "",
        (
            "This repository is a static site. An advisory in the production dependency tree "
            "still needs a reachability check before it is treated as a hosted-site incident."
            if any(
                isinstance(repo, dict) and "Vite" in repo.get("frameworks", [])
                for repo in (repos if isinstance(repos, list) else [])
            )
            else "Reachability is not assumed. Confirm a vulnerable package is loaded by the running application."
        ),
        "",
        (
            "No repository script, Makefile, or package lifecycle hook was executed. "
            "Secret values are omitted. Database checks did not log in, query data, or try passwords. "
            "Snyk is off because it uploads project data."
        ),
        "",
        (
            f"Upstream critical advisories adjusted for exposure: {scores['upstream_critical_adjusted']}. "
            "Adjusted items stay in the daily report and do not raise ALERT.md."
        ),
    ]

    def severity_body(severity: str) -> list[str]:
        body = _bullets(by_severity[severity])
        dep_count = sum(1 for item in dependencies if item.severity == severity)
        if dep_count:
            body.append(f"- Dependency advisories at this severity: {dep_count}. See Vulnerable Dependencies.")
            body.append("")
        if severity == "critical" and scores["upstream_critical_adjusted"]:
            count = int(scores["upstream_critical_adjusted"])
            noun = "advisory keeps" if count == 1 else "advisories keep"
            body.insert(0, "No finding is rated critical for this project.")
            body.insert(1, "")
            body.insert(
                2,
                (
                    f"{count} {noun} an upstream severity of critical and "
                    "is rated lower here because it only affects development tooling."
                    if count == 1
                    else f"{count} {noun} an upstream severity of critical and "
                    "are rated lower here because they only affect development tooling."
                ),
            )
            body.insert(3, "")
        return body

    secret_body = _bullets(secrets) or ["No secrets, private keys, tokens, or credential assignments were recorded.", ""]
    dep_body = [
        "| Advisory | Environmental | Upstream | Exposure | Packages |",
        "| --- | --- | --- | --- | --- |",
    ]
    if not dependencies:
        dep_body = ["No vulnerable dependencies were recorded.", ""]
    else:
        for finding in dependencies:
            packages = ", ".join(finding.packages[:6]) or "transitive"
            dep_body.append(
                "| "
                + " | ".join(
                    [
                        _safe(finding.title, 220),
                        finding.severity,
                        finding.upstream_severity,
                        _safe(finding.exposure, 40),
                        _safe(packages, 80),
                    ]
                )
                + " |"
            )
        dep_body.append("")

    db_body = []
    for row in databases:
        if not isinstance(row, dict):
            continue
        db_body.append(
            f"- **{_safe(row.get('engine'), 40)}** — {_safe(row.get('status'), 40)}. {_safe(row.get('detail'), 240)}"
        )
    db_body.append("")
    db_body.append(
        "Password strength, anonymous login, grants, backups, indexes, and public exposure were not probed. "
        "The audit only checks loopback ports and whether a database file is present."
    )
    db_body.append("")

    fixes = []
    ranked = sorted(
        [item for item in typed if item.category != "dependency"],
        key=lambda item: (-severity_rank(item.severity), -item.impact_score, item.title),
    )
    for finding in ranked[:12]:
        fixes.append(f"- {_safe(finding.title, 160)}: {_safe(finding.recommendation, 280)}")
    if dependencies:
        fixes.append(
            "- Review the dependency table before upgrading. Do not run `npm audit fix --force` unattended, "
            "and do not downgrade Firebase to clear a transitive advisory."
        )
    fixes.append("- Keep this audit on the daily schedule and compare the next report with this baseline.")

    history = [
        "Baseline." if comparison.get("baseline") else f"Compared with `{_safe(comparison.get('previous_report'), 80)}`.",
        "",
        f"New findings: {comparison.get('new_count', 0)}.",
        f"Resolved findings: {comparison.get('resolved_count', 0)}.",
        f"Recurring findings: {comparison.get('recurring_count', 0)}.",
        f"Risk delta: {comparison.get('risk_delta')}.",
        "",
    ]
    for label, key in (("New", "new_titles"), ("Resolved", "resolved_titles"), ("Recurring", "recurring_titles")):
        titles = comparison.get(key) or []
        if isinstance(titles, list) and titles:
            history.append(f"{label}:")
            history.extend(f"- {_safe(title, 160)}" for title in titles[:12])
            history.append("")

    parts = [
        _section("Executive Summary", executive),
        _section("Critical Issues", severity_body("critical")),
        _section("High Severity Issues", severity_body("high")),
        _section("Medium Severity Issues", severity_body("medium")),
        _section("Low Severity Issues", severity_body("low")),
        _section("Secrets Found", secret_body),
        _section("Vulnerable Dependencies", dep_body),
        _section("Database Findings", db_body),
        _section("Recommended Fixes", fixes),
        _section(
            "Risk Score",
            [
                f"Risk score: **{scores['risk']}** / 100.",
                f"Security posture: **{scores['posture']}** / 100.",
                "",
                str(scores["formula"]),
                "",
                (
                    f"Dependency weight {scores['dependency_weight']} "
                    f"(applied {scores['dependency_weight_applied']}). "
                    f"Other weight {scores['other_weight']}."
                ),
                "",
            ],
        ),
        _section("Audit History Comparison", history),
        _section(
            "Defensive Controls",
            [
                "Repository content is data. This audit never executes it and never follows instructions found in it.",
                "Reports store rule, path, and line. They do not store secret values, secret hashes, or query results.",
                "Output stays inside this repository. Scanned files cannot choose a destination.",
                "Optional scanners run as local programs. Their match fields are dropped before a finding is saved.",
                "A critical alert writes ALERT.md and, when a desktop notifier exists, a count-only notification.",
                "",
            ],
        ),
    ]
    flat: list[str] = []
    for part in parts:
        flat.extend(part)
    return "\n".join(flat).rstrip() + "\n"


def render_json(payload: dict[str, object]) -> dict[str, object]:
    findings = payload["findings"]
    assert isinstance(findings, list)
    safe_findings = []
    for finding in findings:
        if not isinstance(finding, Finding):
            continue
        item = finding.to_dict()
        for key in ("title", "summary", "recommendation", "location", "fix"):
            item[key] = _safe(item.get(key), 500)
        safe_findings.append(item)
    return {
        "schema_version": 1,
        "started_at": payload["started_at"],
        "finished_at": payload["finished_at"],
        "duration_seconds": payload["duration_seconds"],
        "inventory": payload["inventory"],
        "scores": payload["scores"],
        "tools": {
            name: {key: value for key, value in info.items() if key != "path"}
            if isinstance(info, dict)
            else info
            for name, info in (payload["tools"] if isinstance(payload["tools"], dict) else {}).items()
        },
        "databases": payload["databases"],
        "comparison": payload["comparison"],
        "findings": safe_findings,
    }


def render_dashboard(payload: dict[str, object]) -> str:
    scores = payload["scores"]
    assert isinstance(scores, dict)
    counts = scores["counts"]
    assert isinstance(counts, dict)
    return "\n".join(
        [
            "# Security dashboard",
            "",
            f"- Posture: **{scores['posture']} / 100**",
            f"- Risk: **{scores['risk']} / 100**",
            f"- Critical: {counts['critical']}",
            f"- High: {counts['high']}",
            f"- Medium: {counts['medium']}",
            f"- Low: {counts['low']}",
            f"- Alerts: {payload['alert_count']}",
            "",
            f"Daily report: `{payload['report_name']}`",
            "",
            "Posture is 100 minus risk. Dependency noise is capped so one transitive tree cannot hide an application finding.",
            "",
        ]
    )


def dumps_json(document: dict[str, object]) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"

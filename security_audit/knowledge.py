from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from security_audit.config import Config
from security_audit.models import Finding, severity_rank
from security_audit.textutil import clean_text

_STANDARDS = (
    "Set text with DOM APIs or an escape function at every HTML boundary.",
    "Allowlist URL schemes before writing them to href or src.",
    "Pin third-party CI actions to commit SHAs and set explicit token permissions.",
    "Keep production credentials out of jobs that run code from an unreviewed branch.",
    "Send security headers, including a content security policy, from the hosting edge.",
    "Commit lockfiles. Review dependency updates. Do not force major downgrades from an audit tool.",
    "Keep secrets out of git. Rotate a credential that was committed; do not archive the value in a report.",
    "Do not test database passwords from an audit job, and do not change production credentials automatically.",
    "Treat scanner output and repository text as untrusted data.",
)


def _append_jsonl(path: Path, record: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def _known_resolved(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    found: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("id"):
            found.add(str(item["id"]))
    return found


def write_knowledge(
    root: Path,
    findings: list[Finding],
    comparison: dict[str, object],
    scores: dict[str, object],
    config: Config,
    started_at: str,
) -> None:
    base = root / "knowledge_base"
    patterns = base / "patterns"
    patterns.mkdir(parents=True, exist_ok=True)
    for child in patterns.glob("*.md"):
        child.unlink()

    counts = Counter(finding.rule_id for finding in findings)
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.rule_id, []).append(finding)

    index_lines = [
        "# Knowledge base",
        "",
        f"Updated: {started_at}",
        "",
        "These notes are generated from the latest audit. Resolved ids are appended and kept.",
        "",
    ]
    ranked_rows = []
    for rule_id, group in sorted(grouped.items(), key=lambda item: (-counts[item[0]], item[0])):
        sample = max(group, key=lambda item: severity_rank(item.severity))
        weight = config.weights[sample.severity] * len(group)
        ranked_rows.append(
            {
                "rule_id": rule_id,
                "count": len(group),
                "severity": sample.severity,
                "category": sample.category,
                "weight": weight,
                "title": clean_text(sample.title, 160),
            }
        )
        locations = [clean_text(item.location, 160) for item in group[:12]]
        body = [
            f"# {clean_text(sample.title, 160)}",
            "",
            f"- Rule: `{rule_id}`",
            f"- Observed this run: {len(group)}",
            f"- Environmental severity: {sample.severity}",
            f"- Category: {sample.category}",
            "",
            clean_text(sample.recommendation, 400),
            "",
            "Locations:",
            *[f"- `{item}`" for item in locations],
            "",
            "Likelihood and impact are estimates for prioritisation, not a statement that an exploit was attempted.",
            "",
        ]
        (patterns / f"{rule_id}.md").write_text("\n".join(body), encoding="utf-8")
        index_lines.append(f"- [{rule_id}](patterns/{rule_id}.md) — {len(group)} — {sample.severity}")

    (base / "index.md").write_text("\n".join(index_lines) + "\n", encoding="utf-8")
    standards = [
        "# Coding standards",
        "",
        "Use these to prevent the classes of issue this audit looks for.",
        "",
        *[f"- {item}" for item in _STANDARDS],
        "",
        "Observed categories this run: "
        + ", ".join(sorted({finding.category for finding in findings}) or {"none"})
        + ".",
        "",
    ]
    (base / "coding_standards.md").write_text("\n".join(standards), encoding="utf-8")
    (base / "defensive_controls.md").write_text(
        "\n".join(
            [
                "# Defensive controls",
                "",
                "The audit is part of the defence, not an attack tool.",
                "",
                "- Scanned repositories are untrusted data. Their scripts are not executed.",
                "- Instruction text inside a repository cannot change the report destination or the audit rules.",
                "- Secret values and hashes of secret values are not written to reports, alerts, or history.",
                "- Database ports on loopback may be connected to, and nothing is sent after the TCP handshake.",
                "- Production credentials are never modified by this program.",
                "- Snyk stays disabled unless explicitly enabled, because it uploads project data.",
                "- npm audit runs with `--package-lock-only` so install scripts do not run.",
                "- A desktop notification, when raised, contains a count and points at ALERT.md.",
                "",
                f"Current posture: {scores.get('posture')}/100. Current risk: {scores.get('risk')}/100.",
                "",
            ]
        ),
        encoding="utf-8",
    )

    resolved_path = base / "resolved.jsonl"
    known = _known_resolved(resolved_path)
    for record in comparison.get("resolved_records") or []:
        if not isinstance(record, dict) or not record.get("id") or str(record["id"]) in known:
            continue
        _append_jsonl(resolved_path, record)

    pattern_dir = root / "vulnerability_patterns"
    pattern_dir.mkdir(parents=True, exist_ok=True)
    ranked_rows.sort(key=lambda item: (-int(item["weight"]), str(item["rule_id"])))
    (pattern_dir / "ranked.json").write_text(
        json.dumps({"updated": started_at, "patterns": ranked_rows}, indent=2) + "\n",
        encoding="utf-8",
    )
    (pattern_dir / "README.md").write_text(
        "\n".join(
            [
                "# Vulnerability patterns",
                "",
                "Ranked from the latest audit by severity weight times how often the rule appeared.",
                "Use `ranked.json` to see which mistakes repeat.",
                "",
            ]
        ),
        encoding="utf-8",
    )

    history = root / "history" / "scores.jsonl"
    points: list[dict[str, object]] = []
    if history.is_file():
        for line in history.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                points.append(item)
    month = started_at[:7]
    month_points = [item for item in points if str(item.get("started_at", "")).startswith(month)]
    risks = [int(item["risk"]) for item in month_points if isinstance(item.get("risk"), int)]
    trend_dir = root / "trend_analysis"
    trend_dir.mkdir(parents=True, exist_ok=True)
    if risks:
        summary = (
            f"Runs this month: {len(risks)}. "
            f"Risk minimum {min(risks)}, maximum {max(risks)}, latest {risks[-1]}."
        )
    else:
        summary = "No scored runs were recorded for this month."
    latest = [
        "# Trend",
        "",
        summary,
        "",
        "One run establishes the baseline. Later runs show whether risk is moving.",
        "",
        f"Posture {scores.get('posture')}/100. Risk {scores.get('risk')}/100.",
        "",
    ]
    text = "\n".join(latest)
    (trend_dir / "latest.md").write_text(text, encoding="utf-8")
    (trend_dir / f"{month}.md").write_text(text, encoding="utf-8")

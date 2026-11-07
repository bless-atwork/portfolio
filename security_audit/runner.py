from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from security_audit.alerts import write_alerts
from security_audit.config import Config, load_config
from security_audit.inventory import inventory_repository, machine_git_counts
from security_audit.knowledge import write_knowledge
from security_audit.models import AuditResult, Finding
from security_audit.render import dumps_json, render_dashboard, render_json, render_markdown
from security_audit.scanners.database import scan_databases
from security_audit.scanners.dependencies import scan_dependencies
from security_audit.scanners.iac import scan_iac
from security_audit.scanners.permissions import scan_permissions
from security_audit.scanners.sast import scan_sast
from security_audit.scanners.secrets import scan_secrets
from security_audit.scanners.tools import _failure, scan_tools
from security_audit.scoring import score_findings
from security_audit.textutil import clean_text

_ADVISORY_MARKERS = ("GHSA-", "CVE-")


def _canonical(advisory_id: str) -> str:
    upper = advisory_id.upper()
    for marker in _ADVISORY_MARKERS:
        index = upper.find(marker)
        if index == -1:
            continue
        token = upper[index:].split()[0].strip(").,]}>")
        if marker == "GHSA-" and token.count("-") >= 3:
            return token
        if marker == "CVE-":
            return token.split("/")[0]
    return advisory_id


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = _canonical(finding.advisory_id) if finding.advisory_id else finding.id
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _mark_alerts(findings: list[Finding], config: Config) -> None:
    for finding in findings:
        finding.alert = (
            finding.severity in config.alert_severities and finding.exposure in config.alert_exposures
        )


def _guard(name: str, fn):
    try:
        return fn()
    except Exception as exc:
        return [_failure(name, exc.__class__.__name__)]


def _previous_report(root: Path) -> tuple[dict[str, object] | None, str]:
    directory = root / "security_reports"
    if not directory.is_dir():
        return None, ""
    files = sorted(directory.glob("security_report_*.json"))
    if not files:
        return None, ""
    latest = files[-1]
    try:
        data = json.loads(latest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, latest.name
    if not isinstance(data, dict):
        return None, latest.name
    return data, latest.name


def _compare(
    previous: dict[str, object] | None,
    previous_name: str,
    findings: list[Finding],
    risk: int,
) -> dict[str, object]:
    if previous is None:
        return {
            "baseline": True,
            "previous_report": "",
            "new_count": len(findings),
            "resolved_count": 0,
            "recurring_count": 0,
            "risk_delta": None,
            "new_titles": [clean_text(item.title, 160) for item in findings[:12]],
            "resolved_titles": [],
            "recurring_titles": [],
            "resolved_records": [],
        }
    prev_items = previous.get("findings")
    prev_map: dict[str, dict[str, object]] = {}
    if isinstance(prev_items, list):
        for item in prev_items:
            if isinstance(item, dict) and item.get("id"):
                prev_map[str(item["id"])] = item
    curr_map = {item.id: item for item in findings}
    new_ids = [key for key in curr_map if key not in prev_map]
    resolved_ids = [key for key in prev_map if key not in curr_map]
    recurring_ids = [key for key in curr_map if key in prev_map]
    previous_scores = previous.get("scores")
    previous_risk = previous_scores.get("risk") if isinstance(previous_scores, dict) else None
    delta = risk - previous_risk if isinstance(previous_risk, int) else None
    resolved_records = []
    for key in resolved_ids:
        item = prev_map[key]
        resolved_records.append(
            {
                "id": key,
                "rule_id": clean_text(item.get("rule_id"), 80),
                "title": clean_text(item.get("title"), 160),
                "location": clean_text(item.get("location"), 180),
            }
        )
    return {
        "baseline": False,
        "previous_report": previous_name,
        "new_count": len(new_ids),
        "resolved_count": len(resolved_ids),
        "recurring_count": len(recurring_ids),
        "risk_delta": delta,
        "new_titles": [clean_text(curr_map[key].title, 160) for key in new_ids[:12]],
        "resolved_titles": [str(record["title"]) for record in resolved_records[:12]],
        "recurring_titles": [clean_text(curr_map[key].title, 160) for key in recurring_ids[:12]],
        "resolved_records": resolved_records,
    }


def _append(path: Path, record: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def run_audit(
    root: Path,
    *,
    offline: bool = False,
    notify: bool = True,
    machine_inventory: bool | None = None,
) -> AuditResult:
    root = root.resolve()
    config = load_config(root)
    if machine_inventory is None:
        machine_inventory = config.machine_inventory
    started = datetime.now().astimezone()
    started_at = started.isoformat(timespec="seconds")
    log_dir = root / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"security-audit-{started.strftime('%Y%m%dT%H%M%S%z')}.log"
    log_lines = [f"start {started_at}", "secret values are not written to this log"]

    repo = inventory_repository(root, config)
    repo["path"] = "."
    machine = (
        machine_git_counts(Path.home())
        if machine_inventory
        else {"counts": {}, "status": "skipped"}
    )
    inventory = {"repositories": [repo], "machine_git": machine}
    log_lines.append(f"repositories {repo['name']}")

    findings: list[Finding] = []
    findings.extend(_guard("secrets", lambda: scan_secrets(root, config)))
    findings.extend(_guard("sast", lambda: scan_sast(root, config)))
    findings.extend(_guard("iac", lambda: scan_iac(root, config)))
    findings.extend(_guard("permissions", lambda: scan_permissions(root, config)))
    try:
        db_findings, databases = scan_databases(root, config)
    except Exception as exc:
        db_findings = [_failure("database", exc.__class__.__name__)]
        databases = [{"engine": "all", "status": "scan_failed", "detail": exc.__class__.__name__}]
    findings.extend(db_findings)
    findings.extend(
        _guard("dependencies", lambda: scan_dependencies(root, config, offline=offline))
    )
    try:
        tool_findings, tools = scan_tools(root, config, offline=offline)
    except Exception as exc:
        tool_findings = [_failure("tools", exc.__class__.__name__)]
        tools = {}
    findings.extend(tool_findings)
    if (
        isinstance(tools.get("npm"), dict)
        and not offline
        and config.npm_audit
        and (root / "package-lock.json").is_file()
    ):
        tools["npm"]["available"] = True
        tools["npm"]["invoked"] = True
    findings = _dedupe(findings)
    _mark_alerts(findings, config)
    scores = score_findings(findings, config)
    previous, previous_name = _previous_report(root)
    comparison = _compare(previous, previous_name, findings, int(scores["risk"]))

    finished = datetime.now().astimezone()
    finished_at = finished.isoformat(timespec="seconds")
    duration = round((finished - started).total_seconds(), 3)
    stamp = started.strftime("%Y_%m_%d")
    report_name = f"security_report_{stamp}"
    db_names = [str(row.get("engine")) for row in databases if isinstance(row, dict)]
    log_lines.append("databases " + ", ".join(db_names))
    log_lines.append(f"end {finished_at}")
    log_lines.append(f"duration_seconds {duration}")
    log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")

    execution = {
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": duration,
        "repositories": [repo["name"]],
        "databases": [
            {"engine": row.get("engine"), "status": row.get("status")}
            for row in databases
            if isinstance(row, dict)
        ],
        "risk": scores["risk"],
        "posture": scores["posture"],
        "counts": scores["counts"],
        "alerts": sum(1 for item in findings if item.alert),
    }
    _append(root / "history" / "executions.jsonl", execution)
    _append(
        root / "history" / "scores.jsonl",
        {
            "started_at": started_at,
            "risk": scores["risk"],
            "posture": scores["posture"],
            "alerts": execution["alerts"],
        },
    )

    payload = {
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": duration,
        "inventory": inventory,
        "findings": findings,
        "databases": databases,
        "tools": tools,
        "scores": scores,
        "comparison": comparison,
        "alert_count": execution["alerts"],
        "report_name": f"{report_name}.md",
    }
    markdown = render_markdown(payload)
    document = render_json(payload)
    dashboard = render_dashboard(payload)
    for folder in ("security_reports", "reports"):
        directory = root / folder
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{report_name}.md").write_text(markdown, encoding="utf-8")
        (directory / f"{report_name}.json").write_text(dumps_json(document), encoding="utf-8")
    (root / "security_reports" / "DASHBOARD.md").write_text(dashboard, encoding="utf-8")
    write_knowledge(root, findings, comparison, scores, config, started_at)
    write_alerts(root, findings, stamp, started_at, notify=notify)

    summary = (
        f"posture={scores['posture']} risk={scores['risk']} "
        f"critical={scores['counts']['critical']} high={scores['counts']['high']} "
        f"medium={scores['counts']['medium']} low={scores['counts']['low']} "
        f"alerts={execution['alerts']} report=security_reports/{report_name}.md"
    )
    return AuditResult(
        started_at=started_at,
        finished_at=finished_at,
        duration_seconds=duration,
        inventory=inventory,
        findings=findings,
        databases=databases,
        tools=tools,
        scores=scores,
        comparison=comparison,
        summary_line=summary,
        report_markdown=markdown,
        report_json=document,
    )

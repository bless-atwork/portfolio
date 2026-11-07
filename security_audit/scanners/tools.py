from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from security_audit.config import Config
from security_audit.models import Finding, normalize_severity
from security_audit.textutil import clean_text, redact
from security_audit.scanners.secrets import compiled_patterns

_PRIORITY = (
    "trivy",
    "semgrep",
    "gitleaks",
    "osv-scanner",
    "dependency-check",
    "safety",
    "bandit",
    "npm",
    "snyk",
    "sqlfluff",
    "checkov",
)


def _resolve(root: Path, name: str) -> str | None:
    candidate = root / "security_audit" / ".tools" / "bin" / name
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    return shutil.which(name)


def _run(cmd: list[str], cwd: Path, timeout: int) -> tuple[int, str, str]:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _failure(name: str, detail: str) -> Finding:
    patterns = compiled_patterns()
    return Finding(
        rule_id="scanner-failed",
        title=f"{name} did not finish",
        severity="low",
        upstream_severity="low",
        exposure="development-tooling",
        category="tooling",
        location=name,
        summary=clean_text(redact(detail, patterns), 240),
        recommendation="Re-run the scanner after checking its local installation. Repository code was not executed.",
        likelihood="low",
        impact="low",
        likelihood_score=1,
        impact_score=1,
        source=name,
    )


def _gitleaks(root: Path, binary: str) -> list[Finding]:
    with tempfile.TemporaryDirectory(prefix="audit-gitleaks-") as tmp:
        report = Path(tmp) / "report.json"
        code, _stdout, stderr = _run(
            [
                binary,
                "detect",
                "--source",
                str(root),
                "--report-format",
                "json",
                "--report-path",
                str(report),
                "--redact=100",
                "--no-banner",
                "--exit-code",
                "0",
            ],
            root,
            180,
        )
        if not report.is_file():
            if code not in (0, 1):
                return [_failure("gitleaks", stderr or "no report")]
            return []
        try:
            payload = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return [_failure("gitleaks", "report was not valid json")]
    items = payload if isinstance(payload, list) else []
    if isinstance(payload, dict):
        maybe = payload.get("findings") or payload.get("Results") or []
        items = maybe if isinstance(maybe, list) else []
    findings: list[Finding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        rule = clean_text(item.get("RuleID") or item.get("Description") or "gitleaks", 80)
        path = clean_text(item.get("File") or ".", 180)
        line = item.get("StartLine")
        where = f"{path}:{line}" if isinstance(line, int) else path
        findings.append(
            Finding(
                rule_id=f"gitleaks-{rule}",
                title=f"Gitleaks rule {rule}",
                severity="high",
                upstream_severity="high",
                exposure="secret",
                category="secret",
                location=where,
                summary="Gitleaks reported a match. The matched text is omitted.",
                recommendation="Rotate the credential, remove it from the working tree and git history, and keep the replacement out of git.",
                likelihood="medium",
                impact="high",
                likelihood_score=3,
                impact_score=5,
                source="gitleaks",
                advisory_id=rule,
            )
        )
    return findings


def _trivy(root: Path, binary: str) -> list[Finding]:
    code, stdout, stderr = _run(
        [
            binary,
            "fs",
            "--scanners",
            "misconfig",
            "--skip-db-update",
            "--skip-dirs",
            "node_modules,dist,.git,security_audit/.tools",
            "--format",
            "json",
            "--quiet",
            str(root),
        ],
        root,
        180,
    )
    if code not in (0, 1) or not stdout.strip():
        return [_failure("trivy", stderr or "no json")]
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return [_failure("trivy", "output was not valid json")]
    findings: list[Finding] = []
    results = payload.get("Results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        return findings
    for result in results:
        if not isinstance(result, dict):
            continue
        target = clean_text(result.get("Target") or ".", 180)
        misconfigs = result.get("Misconfigurations") or []
        if not isinstance(misconfigs, list):
            continue
        for item in misconfigs:
            if not isinstance(item, dict):
                continue
            severity = normalize_severity(str(item.get("Severity") or "low"))
            check = clean_text(item.get("ID") or "trivy", 80)
            title = clean_text(item.get("Title") or check, 160)
            findings.append(
                Finding(
                    rule_id=f"trivy-{check}",
                    title=title,
                    severity=severity,
                    upstream_severity=severity,
                    exposure="production-runtime",
                    category="iac",
                    location=target,
                    summary=clean_text(item.get("Description") or item.get("Message") or title, 240),
                    recommendation=clean_text(
                        item.get("Resolution") or "Apply the configuration change described by the check.",
                        240,
                    ),
                    likelihood="low",
                    impact="medium",
                    likelihood_score=2,
                    impact_score=3,
                    source="trivy",
                    advisory_id=check,
                )
            )
    return findings


def _osv(root: Path, binary: str) -> list[Finding]:
    lock = root / "package-lock.json"
    if not lock.is_file():
        return []
    with tempfile.TemporaryDirectory(prefix="audit-osv-") as tmp:
        report = Path(tmp) / "osv.json"
        code, _stdout, stderr = _run(
            [
                binary,
                "scan",
                "source",
                "-L",
                str(lock),
                "--format",
                "json",
                "--verbosity",
                "error",
                "--output-file",
                str(report),
            ],
            root,
            180,
        )
        if not report.is_file():
            if code not in (0, 1):
                return [_failure("osv-scanner", stderr or "no report")]
            return []
        try:
            payload = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return [_failure("osv-scanner", "report was not valid json")]
    findings: list[Finding] = []
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        return findings
    for result in results:
        if not isinstance(result, dict):
            continue
        packages = result.get("packages") or []
        if not isinstance(packages, list):
            continue
        for package in packages:
            if not isinstance(package, dict):
                continue
            meta = package.get("package") if isinstance(package.get("package"), dict) else {}
            name = clean_text(meta.get("name") or "dependency", 80)
            for vuln in package.get("vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                advisory = clean_text(vuln.get("id") or "", 80)
                title = clean_text(vuln.get("summary") or advisory, 180)
                findings.append(
                    Finding(
                        rule_id="osv-advisory",
                        title=title or advisory,
                        severity="medium",
                        upstream_severity="medium",
                        exposure="production-dependency-tree",
                        category="dependency",
                        location="package-lock.json",
                        summary=title or advisory,
                        recommendation="Update the affected package when a patched release is available.",
                        likelihood="low",
                        impact="medium",
                        likelihood_score=2,
                        impact_score=3,
                        source="osv-scanner",
                        advisory_id=advisory,
                        packages=(name,),
                    )
                )
    return findings


def scan_tools(
    root: Path, config: Config, *, offline: bool
) -> tuple[list[Finding], dict[str, object]]:
    status: dict[str, object] = {}
    findings: list[Finding] = []
    for name in _PRIORITY:
        path = _resolve(root, name)
        status[name] = {"available": path is not None, "path": path or "", "invoked": False}
    if not config.external_scanners:
        return findings, status

    gitleaks = status["gitleaks"]["path"]
    if gitleaks:
        status["gitleaks"]["invoked"] = True
        try:
            findings.extend(_gitleaks(root, str(gitleaks)))
        except (OSError, subprocess.TimeoutExpired) as exc:
            findings.append(_failure("gitleaks", exc.__class__.__name__))

    trivy = status["trivy"]["path"]
    if trivy:
        status["trivy"]["invoked"] = True
        try:
            findings.extend(_trivy(root, str(trivy)))
        except (OSError, subprocess.TimeoutExpired) as exc:
            findings.append(_failure("trivy", exc.__class__.__name__))

    osv = status["osv-scanner"]["path"]
    if osv and not offline:
        status["osv-scanner"]["invoked"] = True
        try:
            findings.extend(_osv(root, str(osv)))
        except (OSError, subprocess.TimeoutExpired) as exc:
            findings.append(_failure("osv-scanner", exc.__class__.__name__))

    status["snyk"]["invoked"] = False
    status["snyk"]["reason"] = (
        "enabled in config"
        if config.snyk
        else "not invoked; Snyk uploads project data and stays off unless network.snyk is true"
    )
    for name in ("semgrep", "safety", "bandit", "sqlfluff", "checkov", "dependency-check"):
        if status[name]["available"]:
            status[name]["reason"] = "installed; built-in checks ran instead of a networked ruleset"
    return findings, status

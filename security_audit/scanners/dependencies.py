from __future__ import annotations

import json
import subprocess
from pathlib import Path

from security_audit.config import Config
from security_audit.models import Finding, downgrade_severity, normalize_severity
from security_audit.textutil import clean_text

_ECOSYSTEMS = {
    "requirements.txt": "Python",
    "pyproject.toml": "Python",
    "Pipfile.lock": "Python",
    "composer.lock": "PHP",
    "Gemfile.lock": "Ruby",
    "pom.xml": "Maven",
    "build.gradle": "Gradle",
    "build.gradle.kts": "Gradle",
    "Cargo.lock": "Rust",
    "go.mod": "Go",
}


def _run_npm_audit(root: Path, extra: list[str]) -> dict[str, object] | None:
    try:
        proc = subprocess.run(
            ["npm", "audit", "--json", "--package-lock-only", *extra],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode not in (0, 1) or not proc.stdout.strip():
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    return data


def _advisories(audit: dict[str, object]) -> dict[str, dict[str, object]]:
    found: dict[str, dict[str, object]] = {}
    vulnerabilities = audit.get("vulnerabilities")
    if not isinstance(vulnerabilities, dict):
        return found
    for package, info in vulnerabilities.items():
        if not isinstance(info, dict):
            continue
        vias = info.get("via")
        if not isinstance(vias, list):
            continue
        for via in vias:
            if not isinstance(via, dict) or not via.get("title"):
                continue
            advisory = str(via.get("url") or via.get("source") or via.get("title"))
            entry = found.setdefault(
                advisory,
                {
                    "title": clean_text(via.get("title"), 200),
                    "severity": normalize_severity(str(via.get("severity", "low"))),
                    "url": str(via.get("url") or ""),
                    "packages": [],
                    "fix": "",
                },
            )
            if package not in entry["packages"]:
                entry["packages"].append(str(package))
            fix = info.get("fixAvailable")
            if fix is True:
                entry["fix"] = "npm reports a compatible fix. Review it before applying."
            elif isinstance(fix, dict):
                version = clean_text(fix.get("version"), 40)
                if fix.get("isSemVerMajor"):
                    entry["fix"] = (
                        f"npm suggests {fix.get('name')} {version}, a major change. "
                        "It was not applied automatically."
                    )
                elif version:
                    entry["fix"] = f"npm reports a fix via {fix.get('name')} {version}."
    return found


def scan_dependencies(root: Path, config: Config, *, offline: bool) -> list[Finding]:
    findings: list[Finding] = []
    for name, ecosystem in _ECOSYSTEMS.items():
        if (root / name).is_file():
            findings.append(
                Finding(
                    rule_id="unscanned-ecosystem",
                    title=f"{ecosystem} dependencies are not scanned by an installed tool",
                    severity="low",
                    upstream_severity="low",
                    exposure="development-tooling",
                    category="dependency",
                    location=name,
                    summary=f"{name} is present and no local scanner for {ecosystem} ran.",
                    recommendation="Install the ecosystem scanner from security_audit/install.sh and re-run the audit.",
                    likelihood="low",
                    impact="medium",
                    likelihood_score=2,
                    impact_score=3,
                    source="builtin",
                )
            )
    lock = root / "package-lock.json"
    manifest = root / "package.json"
    if manifest.is_file() and not lock.is_file():
        findings.append(
            Finding(
                rule_id="npm-lockfile-missing",
                title="npm lockfile is missing",
                severity="medium",
                upstream_severity="medium",
                exposure="application",
                category="dependency",
                location="package.json",
                summary="package.json has no package-lock.json, so installs are not reproducible.",
                recommendation="Commit package-lock.json and install with npm ci.",
                likelihood="medium",
                impact="medium",
                likelihood_score=3,
                impact_score=3,
                source="builtin",
            )
        )
        return findings
    if not lock.is_file() or offline or not config.npm_audit:
        return findings

    full = _run_npm_audit(root, [])
    production = _run_npm_audit(root, ["--omit=dev"])
    if full is None:
        findings.append(
            Finding(
                rule_id="npm-audit-unavailable",
                title="npm audit did not return a report",
                severity="low",
                upstream_severity="low",
                exposure="development-tooling",
                category="dependency",
                location="package-lock.json",
                summary="npm audit could not be parsed. Dependency coverage is incomplete for this run.",
                recommendation="Re-run online with npm available. The audit does not execute package lifecycle scripts.",
                likelihood="low",
                impact="low",
                likelihood_score=1,
                impact_score=2,
                source="npm-audit",
            )
        )
        return findings

    production_ids = set(_advisories(production).keys()) if production else set()
    for advisory_id, entry in _advisories(full).items():
        upstream = str(entry["severity"])
        exposure = (
            "production-dependency-tree"
            if advisory_id in production_ids
            else "development-tooling"
        )
        severity = upstream
        if config.downgrade_development_severities and exposure == "development-tooling":
            severity = downgrade_severity(upstream)
        packages = tuple(entry["packages"][:12])
        url = str(entry["url"])
        summary = entry["title"]
        if url:
            summary = f"{summary} ({url})"
        findings.append(
            Finding(
                rule_id="npm-advisory",
                title=str(entry["title"]),
                severity=severity,
                upstream_severity=upstream,
                exposure=exposure,
                category="dependency",
                location="package-lock.json",
                summary=clean_text(summary, 300),
                recommendation=str(entry["fix"])
                or "Update the parent package when a patched release is available. Do not use npm audit fix --force unattended.",
                likelihood="low" if exposure == "development-tooling" else "medium",
                impact="medium" if exposure == "development-tooling" else "high",
                likelihood_score=2 if exposure == "development-tooling" else 3,
                impact_score=2 if exposure == "development-tooling" else 4,
                source="npm-audit",
                advisory_id=advisory_id,
                packages=packages,
                fix=str(entry["fix"]),
            )
        )
    return findings

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from security_audit.config import Config
from security_audit.files import iter_files, location, read_text
from security_audit.models import Finding

_PLACEHOLDER = re.compile(
    r"(?i)(changeme|placeholder|your[-_]|example|dummy|sample|redacted|"
    r"todo|process\.env|import\.meta\.env|\$\{\{|<{2}|xxxxx|not-a-secret)"
)
_SENSITIVE_NAMES = {
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "credentials.json",
    "service-account.json",
    "serviceaccountkey.json",
}
_SENSITIVE_SUFFIXES = {".pem", ".p12", ".pfx"}


def _rules() -> list[dict[str, object]]:
    path = Path(__file__).resolve().parents[1] / "rules" / "secret_patterns.json"
    loaded = json.loads(path.read_text(encoding="utf-8"))
    rules: list[dict[str, object]] = []
    for item in loaded:
        item = dict(item)
        item["compiled"] = re.compile(str(item["regex"]))
        rules.append(item)
    return rules


def compiled_patterns() -> list[tuple[str, re.Pattern[str]]]:
    return [(str(rule["id"]), rule["compiled"]) for rule in _rules()]


def _tracked(root: Path) -> set[str]:
    try:
        proc = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=root,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    if proc.returncode != 0:
        return set()
    text = proc.stdout.decode("utf-8", errors="replace")
    return {item for item in text.split("\0") if item}


def _finding(rule: dict[str, object], root: Path, path: Path, line: int | None) -> Finding:
    severity = str(rule["severity"])
    where = location(root, path, line)
    return Finding(
        rule_id=str(rule["id"]),
        title=str(rule["title"]),
        severity=severity,
        upstream_severity=severity,
        exposure=str(rule["exposure"]),
        category="secret",
        location=where,
        summary=f"{rule['title']} detected. The value is omitted from this report.",
        recommendation=str(rule["recommendation"]),
        likelihood="medium",
        impact="high",
        likelihood_score=3,
        impact_score=5,
        source="builtin",
    )


def scan_secrets(root: Path, config: Config) -> list[Finding]:
    rules = _rules()
    tracked = _tracked(root)
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def add(rule: dict[str, object], path: Path, line: int | None) -> None:
        where = location(root, path, line)
        key = (str(rule["id"]), where)
        if key in seen:
            return
        seen.add(key)
        findings.append(_finding(rule, root, path, line))

    for path in iter_files(root, config, include_binary=True):
        rel = path.relative_to(root.resolve()).as_posix()
        lowered = path.name.lower()
        if lowered in _SENSITIVE_NAMES or path.suffix.lower() in _SENSITIVE_SUFFIXES:
            severity = "critical" if rel in tracked else "high"
            rule = {
                "id": "sensitive-filename",
                "title": "Sensitive credential filename",
                "severity": severity,
                "exposure": "secret",
                "recommendation": "Remove the file from the repository and history, then rotate the credential it holds.",
            }
            add(rule, path, None)
        if path.name == ".env" and rel in tracked:
            add(
                {
                    "id": "tracked-env-file",
                    "title": "Environment file is tracked by git",
                    "severity": "critical",
                    "exposure": "secret",
                    "recommendation": "Stop tracking .env, confirm gitignore covers it, and rotate every value that was committed.",
                },
                path,
                None,
            )

    for path in iter_files(root, config):
        text = read_text(path, config.max_file_bytes)
        if text is None:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            if len(line) > 500:
                continue
            for rule in rules:
                match = rule["compiled"].search(line)
                if match is None:
                    continue
                if rule.get("placeholder"):
                    value = match.groupdict().get("value", match.group(0))
                    if _PLACEHOLDER.search(value):
                        continue
                add(rule, path, line_number)
    return findings

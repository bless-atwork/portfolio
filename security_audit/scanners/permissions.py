from __future__ import annotations

from pathlib import Path

from security_audit.config import Config
from security_audit.files import iter_files, location
from security_audit.models import Finding


def scan_permissions(root: Path, config: Config) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for path in iter_files(root, config, include_binary=True):
        try:
            mode = path.stat().st_mode
        except OSError:
            continue
        if mode & 0o002 == 0:
            continue
        where = location(root, path)
        if where in seen:
            continue
        seen.add(where)
        findings.append(
            Finding(
                rule_id="world-writable-file",
                title="File is world-writable",
                severity="medium",
                upstream_severity="medium",
                exposure="application",
                category="permissions",
                location=where,
                summary="Another local user can change this file.",
                recommendation="Remove the world-writable bit and keep secrets readable only by the owner.",
                likelihood="low",
                impact="medium",
                likelihood_score=2,
                impact_score=3,
                source="builtin",
            )
        )
    return findings

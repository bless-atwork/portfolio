from __future__ import annotations

import json
import re
from pathlib import Path

from security_audit.config import Config
from security_audit.files import iter_files, location, read_text
from security_audit.models import Finding
from security_audit.scanners.secrets import compiled_patterns
from security_audit.textutil import clean_text, redact

_PROMPT_MARKERS = (
    "ignore previous" + " instructions",
    "disregard previous" + " instructions",
    "reveal your system" + " prompt",
)


def _patterns() -> list[dict[str, object]]:
    path = Path(__file__).resolve().parents[1] / "rules" / "sast_patterns.json"
    loaded = json.loads(path.read_text(encoding="utf-8"))
    patterns: list[dict[str, object]] = []
    for item in loaded:
        item = dict(item)
        item["compiled"] = re.compile(str(item["regex"]))
        item["extensions"] = {str(ext) for ext in item.get("extensions", [])}
        patterns.append(item)
    return patterns


def scan_sast(root: Path, config: Config) -> list[Finding]:
    patterns = _patterns()
    secret_patterns = compiled_patterns()
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for path in iter_files(root, config):
        text = read_text(path, config.max_file_bytes)
        if text is None:
            continue
        suffix = path.suffix.lower()
        for line_number, line in enumerate(text.splitlines(), start=1):
            if len(line) > 500:
                continue
            for pattern in patterns:
                extensions = pattern["extensions"]
                if extensions and suffix not in extensions:
                    continue
                if pattern["compiled"].search(line) is None:
                    continue
                where = location(root, path, line_number)
                key = (str(pattern["id"]), where)
                if key in seen:
                    continue
                seen.add(key)
                severity = str(pattern["severity"])
                findings.append(
                    Finding(
                        rule_id=str(pattern["id"]),
                        title=str(pattern["title"]),
                        severity=severity,
                        upstream_severity=severity,
                        exposure=str(pattern["exposure"]),
                        category=str(pattern["category"]),
                        location=where,
                        summary=clean_text(redact(line, secret_patterns), 180),
                        recommendation=str(pattern["recommendation"]),
                        likelihood=str(pattern["likelihood"]),
                        impact=str(pattern["impact"]),
                        likelihood_score=int(pattern["likelihood_score"]),
                        impact_score=int(pattern["impact_score"]),
                        source="builtin",
                    )
                )
            lowered = line.lower()
            for marker in _PROMPT_MARKERS:
                if marker not in lowered:
                    continue
                where = location(root, path, line_number)
                key = ("prompt-injection-marker", where)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        rule_id="prompt-injection-marker",
                        title="Untrusted instruction marker in source",
                        severity="low",
                        upstream_severity="low",
                        exposure="application",
                        category="ai-abuse",
                        location=where,
                        summary="A prompt-injection marker is present. The marker text is omitted.",
                        recommendation="Treat repository text as data. Do not let scanned files add instructions for people or tools.",
                        likelihood="low",
                        impact="medium",
                        likelihood_score=2,
                        impact_score=3,
                        source="builtin",
                    )
                )
    return findings

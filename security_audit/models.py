from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field


SEVERITIES = ("critical", "high", "medium", "low")

_SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def normalize_severity(value: str) -> str:
    key = (value or "").strip().lower()
    table = {
        "critical": "critical",
        "high": "high",
        "moderate": "medium",
        "medium": "medium",
        "low": "low",
        "info": "low",
        "informational": "low",
        "unknown": "low",
    }
    return table.get(key, "low")


def downgrade_severity(severity: str) -> str:
    normalized = normalize_severity(severity)
    if normalized == "critical":
        return "high"
    if normalized == "high":
        return "medium"
    if normalized == "medium":
        return "low"
    if normalized == "low":
        return "low"
    raise ValueError(f"unknown severity: {severity}")


def severity_rank(severity: str) -> int:
    normalized = normalize_severity(severity)
    if normalized not in _SEVERITY_ORDER:
        raise ValueError(f"unknown severity: {severity}")
    return _SEVERITY_ORDER[normalized]


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    upstream_severity: str
    exposure: str
    category: str
    location: str
    summary: str
    recommendation: str
    likelihood: str
    impact: str
    likelihood_score: int
    impact_score: int
    source: str = "builtin"
    advisory_id: str = ""
    packages: tuple[str, ...] = ()
    fix: str = ""
    alert: bool = False

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        self.upstream_severity = normalize_severity(self.upstream_severity)
        self.likelihood_score = max(1, min(5, int(self.likelihood_score)))
        self.impact_score = max(1, min(5, int(self.impact_score)))

    @property
    def id(self) -> str:
        raw = f"{self.rule_id}|{self.advisory_id}|{self.location}|{self.title}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["id"] = self.id
        payload["packages"] = list(self.packages)
        return payload


@dataclass
class AuditResult:
    started_at: str
    finished_at: str
    duration_seconds: float
    inventory: dict[str, object]
    findings: list[Finding]
    databases: list[dict[str, object]]
    tools: dict[str, object]
    scores: dict[str, object]
    comparison: dict[str, object]
    summary_line: str = ""
    report_markdown: str = ""
    report_json: dict[str, object] = field(default_factory=dict)

    @property
    def alert(self) -> bool:
        return any(finding.alert for finding in self.findings)

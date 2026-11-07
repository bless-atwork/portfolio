from __future__ import annotations

from security_audit.config import Config
from security_audit.models import SEVERITIES, Finding


def score_findings(findings: list[Finding], config: Config) -> dict[str, object]:
    counts = {severity: 0 for severity in SEVERITIES}
    dependency_weight = 0
    other_weight = 0
    adjusted_critical = 0
    for finding in findings:
        counts[finding.severity] += 1
        weight = config.weights[finding.severity]
        if finding.category == "dependency":
            dependency_weight += weight
        else:
            other_weight += weight
        if finding.upstream_severity == "critical" and finding.severity != "critical":
            adjusted_critical += 1
    dependency_applied = min(config.dependency_penalty_cap, dependency_weight)
    risk = min(100, dependency_applied + other_weight)
    posture = 100 - risk
    formula = (
        "Risk starts at 0. Each finding adds its environmental weight: "
        "critical 25, high 12, medium 5, low 2. "
        f"Dependency weight is capped at {config.dependency_penalty_cap}. "
        "Development-tooling advisories drop one severity before weighting. "
        "Posture is 100 minus risk. Both scores stay between 0 and 100."
    )
    return {
        "risk": risk,
        "posture": posture,
        "counts": counts,
        "dependency_weight": dependency_weight,
        "dependency_weight_applied": dependency_applied,
        "other_weight": other_weight,
        "upstream_critical_adjusted": adjusted_critical,
        "formula": formula,
    }

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from security_audit.models import Finding
from security_audit.runner import run_audit
from security_audit.scoring import score_findings
from security_audit.config import Config

REPO = Path(__file__).resolve().parents[2]
HEADINGS = (
    "# Executive Summary",
    "# Critical Issues",
    "# High Severity Issues",
    "# Medium Severity Issues",
    "# Low Severity Issues",
    "# Secrets Found",
    "# Vulnerable Dependencies",
    "# Database Findings",
    "# Recommended Fixes",
    "# Risk Score",
    "# Audit History Comparison",
)


def _finding(severity: str, category: str = "application") -> Finding:
    return Finding(
        rule_id=f"rule-{severity}-{category}",
        title=f"{severity} {category}",
        severity=severity,
        upstream_severity=severity,
        exposure="application",
        category=category,
        location="src/app.js",
        summary="summary",
        recommendation="fix it",
        likelihood="low",
        impact="low",
        likelihood_score=1,
        impact_score=1,
    )


class ScoringTests(unittest.TestCase):
    def test_dependency_weight_is_capped(self) -> None:
        config = Config(dependency_penalty_cap=35)
        findings = [_finding("high", "dependency") for _ in range(10)]
        scores = score_findings(findings, config)
        self.assertEqual(scores["dependency_weight"], 120)
        self.assertEqual(scores["dependency_weight_applied"], 35)
        self.assertEqual(scores["risk"], 35)
        self.assertEqual(scores["posture"], 65)

    def test_posture_and_risk_sum_to_100(self) -> None:
        scores = score_findings([_finding("low")], Config())
        self.assertEqual(scores["risk"] + scores["posture"], 100)


class AuditTests(unittest.TestCase):
    def test_secret_value_is_omitted_and_alert_is_local(self) -> None:
        root = Path(self._tmp())
        source = root / "src"
        source.mkdir(parents=True)
        secret = "AKIA" + "IOSFODNN7EXAMPLE"
        marker = "ignore previous" + " instructions"
        (source / "config.js").write_text(
            "\n".join(
                [
                    f"const key = '{secret}'",
                    "const password = 'supersecretvalue'",
                    "element.innerHTML = input",
                    f"// {marker}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        outside = root.parent / "outside.js"
        outside.write_text(f"const key = '{secret}'\n", encoding="utf-8")
        (source / "link.js").symlink_to(outside)

        result = run_audit(root, offline=True, notify=False, machine_inventory=False)
        report = (root / "security_reports").glob("security_report_*.md")
        markdown = next(report).read_text(encoding="utf-8")
        document = next((root / "security_reports").glob("security_report_*.json")).read_text(
            encoding="utf-8"
        )
        alert = (root / "ALERT.md").read_text(encoding="utf-8")
        log = next((root / "logs").glob("*.log")).read_text(encoding="utf-8")
        for blob in (markdown, document, alert, log):
            self.assertNotIn(secret, blob)
            self.assertNotIn("supersecretvalue", blob)
            self.assertNotIn(marker, blob)
        self.assertTrue(result.alert)
        for heading in HEADINGS:
            self.assertIn(heading, markdown)
        self.assertIn("Untrusted instruction marker", markdown)
        self.assertIn("HTML is assigned from a string", markdown)
        position = -1
        for heading in HEADINGS:
            found = markdown.find(heading)
            self.assertGreater(found, position)
            position = found

    def test_second_run_records_a_resolved_finding(self) -> None:
        root = Path(self._tmp())
        source = root / "src"
        source.mkdir(parents=True)
        secret = "AKIA" + "IOSFODNN7EXAMPLE"
        target = source / "config.js"
        target.write_text(f"const key = '{secret}'\n", encoding="utf-8")
        first = run_audit(root, offline=True, notify=False, machine_inventory=False)
        self.assertTrue(first.alert)
        target.unlink()
        second = run_audit(root, offline=True, notify=False, machine_inventory=False)
        self.assertGreater(second.comparison["resolved_count"], 0)
        self.assertFalse((root / "ALERT.md").exists())
        resolved = (root / "knowledge_base" / "resolved.jsonl").read_text(encoding="utf-8")
        self.assertNotIn(secret, resolved)

    def test_unpinned_workflow_is_reported(self) -> None:
        root = Path(self._tmp())
        workflow = root / ".github" / "workflows"
        workflow.mkdir(parents=True)
        (workflow / "deploy.yml").write_text(
            "on:\n  pull_request:\njobs:\n  build:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        env:\n          TOKEN: ${{ secrets.EXAMPLE }}\n",
            encoding="utf-8",
        )
        result = run_audit(root, offline=True, notify=False, machine_inventory=False)
        rules = {item.rule_id for item in result.findings}
        self.assertIn("ci-unpinned-action", rules)
        self.assertIn("ci-pr-holds-secrets", rules)
        self.assertIn("ci-default-permissions", rules)

    def test_portfolio_rendering_has_no_html_sink(self) -> None:
        text = (REPO / "src" / "main.js").read_text(encoding="utf-8")
        self.assertNotIn("innerHTML", text)
        self.assertIn("textContent", text)

    def _tmp(self) -> str:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name) / "repo"
        root.mkdir()
        return str(root)


class ReportShapeTests(unittest.TestCase):
    def test_clean_repo_has_database_inventory(self) -> None:
        root = Path(self._tmp())
        (root / "README.md").write_text("hello\n", encoding="utf-8")
        result = run_audit(root, offline=True, notify=False, machine_inventory=False)
        engines = {row["engine"] for row in result.databases}
        self.assertIn("postgresql", engines)
        self.assertIn("sqlite", engines)
        self.assertFalse(result.alert)
        parsed = json.loads(result.report_json and json.dumps(result.report_json))
        self.assertEqual(parsed["schema_version"], 1)

    def _tmp(self) -> str:
        return AuditTests._tmp(self)


if __name__ == "__main__":
    unittest.main()

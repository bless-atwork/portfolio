from __future__ import annotations

import json
import re
from pathlib import Path

from security_audit.config import Config
from security_audit.files import iter_files, location, read_text
from security_audit.models import Finding

_ACTION_USE = re.compile(r"uses:\s*([^\s#]+)")
_SHA = re.compile(r"[0-9a-f]{40}")
_REQUIRED_HEADERS = {
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "x-frame-options",
}


def _add(findings: list[Finding], **kwargs: object) -> None:
    findings.append(
        Finding(
            rule_id=str(kwargs["rule_id"]),
            title=str(kwargs["title"]),
            severity=str(kwargs["severity"]),
            upstream_severity=str(kwargs["severity"]),
            exposure=str(kwargs["exposure"]),
            category=str(kwargs["category"]),
            location=str(kwargs["location"]),
            summary=str(kwargs["summary"]),
            recommendation=str(kwargs["recommendation"]),
            likelihood=str(kwargs["likelihood"]),
            impact=str(kwargs["impact"]),
            likelihood_score=int(kwargs["likelihood_score"]),
            impact_score=int(kwargs["impact_score"]),
            source="builtin",
        )
    )


def _workflow_findings(root: Path, path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    where = location(root, path)
    for match in _ACTION_USE.finditer(text):
        ref = match.group(1).strip()
        if "@" not in ref or ref.startswith("./"):
            continue
        _action, version = ref.rsplit("@", 1)
        if _SHA.fullmatch(version):
            continue
        line = text[: match.start()].count("\n") + 1
        _add(
            findings,
            rule_id="ci-unpinned-action",
            title="GitHub Action is not pinned to a commit",
            severity="medium",
            exposure="ci",
            category="ci",
            location=location(root, path, line),
            summary=f"{ref} can change when the tag moves.",
            recommendation="Pin the action to a 40-character commit SHA and keep the tag in a comment.",
            likelihood="low",
            impact="high",
            likelihood_score=2,
            impact_score=4,
        )
    if "uses:" in text and "permissions:" not in text:
        _add(
            findings,
            rule_id="ci-default-permissions",
            title="Workflow uses the default token permissions",
            severity="medium",
            exposure="ci",
            category="ci",
            location=where,
            summary="The workflow does not set a permissions block.",
            recommendation="Set the minimum permissions the jobs need, usually contents: read.",
            likelihood="low",
            impact="medium",
            likelihood_score=2,
            impact_score=3,
        )
    if re.search(r"(?m)^[\s-]*pull_request\b", text) and "secrets." in text:
        _add(
            findings,
            rule_id="ci-pr-holds-secrets",
            title="Pull request workflow receives repository secrets",
            severity="high",
            exposure="ci",
            category="ci",
            location=where,
            summary=(
                "A pull_request workflow in this repository receives secrets. "
                "A branch pushed to the same repository can change the job that runs. "
                "Fork pull requests do not receive repository secrets."
            ),
            recommendation=(
                "Put deploy jobs in a protected GitHub Environment that requires approval, "
                "and keep long-lived credentials out of jobs that execute code from an unreviewed branch."
            ),
            likelihood="medium",
            impact="high",
            likelihood_score=3,
            impact_score=5,
        )
    if "continue-on-error: true" in text:
        _add(
            findings,
            rule_id="ci-continue-on-error",
            title="A workflow step ignores failures",
            severity="low",
            exposure="ci",
            category="ci",
            location=where,
            summary="continue-on-error hides a failed step from the check result.",
            recommendation="Fail the job when a deploy or security step fails.",
            likelihood="medium",
            impact="low",
            likelihood_score=3,
            impact_score=2,
        )
    return findings


def _firebase_findings(root: Path, path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return findings
    hosting = data.get("hosting") if isinstance(data, dict) else None
    blocks = hosting if isinstance(hosting, list) else [hosting]
    headers: set[str] = set()
    for block in blocks:
        if not isinstance(block, dict):
            continue
        for rule in block.get("headers", []) if isinstance(block.get("headers"), list) else []:
            if not isinstance(rule, dict):
                continue
            for header in rule.get("headers", []) if isinstance(rule.get("headers"), list) else []:
                if isinstance(header, dict) and header.get("key"):
                    headers.add(str(header["key"]).lower())
    missing = sorted(_REQUIRED_HEADERS - headers)
    if missing:
        _add(
            findings,
            rule_id="hosting-security-headers",
            title="Hosting configuration is missing security headers",
            severity="medium",
            exposure="production-runtime",
            category="iac",
            location=location(root, path),
            summary="Missing headers: " + ", ".join(missing),
            recommendation=(
                "Add a content security policy, nosniff, a referrer policy, and frame protection "
                "on Firebase Hosting responses."
            ),
            likelihood="medium",
            impact="medium",
            likelihood_score=3,
            impact_score=3,
        )
    return findings


def _html_findings(root: Path, path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in re.finditer(r"<link\b[^>]*>", text, flags=re.IGNORECASE | re.DOTALL):
        tag = match.group(0)
        if "stylesheet" not in tag.lower() or "http" not in tag.lower():
            continue
        if "integrity=" in tag.lower():
            continue
        line = text[: match.start()].count("\n") + 1
        _add(
            findings,
            rule_id="remote-stylesheet",
            title="Remote stylesheet has no integrity attribute",
            severity="low",
            exposure="production-runtime",
            category="supply-chain",
            location=location(root, path, line),
            summary="A third-party stylesheet is loaded without subresource integrity.",
            recommendation="Self-host the font CSS or pin it with integrity and crossorigin.",
            likelihood="low",
            impact="low",
            likelihood_score=1,
            impact_score=2,
        )
    return findings


def _docker_k8s_terraform(root: Path, path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    name = path.name.lower()
    where = location(root, path)
    if name == "dockerfile" or name.startswith("dockerfile"):
        if re.search(r"(?i)^from\s+\S+:latest\b", text, flags=re.MULTILINE) or re.search(
            r"(?i)^from\s+[^\s:@]+(\s|$)", text, flags=re.MULTILINE
        ):
            _add(
                findings,
                rule_id="docker-floating-base",
                title="Container base image is not pinned",
                severity="medium",
                exposure="production-runtime",
                category="docker",
                location=where,
                summary="The Dockerfile uses a floating base image tag.",
                recommendation="Pin the base image by digest and run the container as a non-root user.",
                likelihood="low",
                impact="medium",
                likelihood_score=2,
                impact_score=3,
            )
        if "user " not in text.lower():
            _add(
                findings,
                rule_id="docker-root-user",
                title="Container does not set a user",
                severity="low",
                exposure="production-runtime",
                category="docker",
                location=where,
                summary="The Dockerfile never switches away from the default user.",
                recommendation="Add a USER instruction for an unprivileged account.",
                likelihood="low",
                impact="medium",
                likelihood_score=2,
                impact_score=3,
            )
    if re.search(r"(?m)^kind:\s*(Deployment|Pod|DaemonSet|StatefulSet)\b", text):
        if re.search(r"privileged:\s*true", text) or "hostNetwork: true" in text or "hostPath:" in text:
            _add(
                findings,
                rule_id="k8s-privileged",
                title="Kubernetes workload has a privileged setting",
                severity="high",
                exposure="production-runtime",
                category="kubernetes",
                location=where,
                summary="The manifest enables privileged, hostNetwork, or hostPath.",
                recommendation="Drop privileged mode and host access unless a reviewed exception requires it.",
                likelihood="medium",
                impact="high",
                likelihood_score=3,
                impact_score=5,
            )
    if path.suffix == ".tf":
        if '0.0.0.0/0' in text or "public-read" in text:
            _add(
                findings,
                rule_id="iac-public-exposure",
                title="Infrastructure opens a public network or storage ACL",
                severity="high",
                exposure="production-runtime",
                category="iac",
                location=where,
                summary="Terraform contains 0.0.0.0/0 or a public-read ACL.",
                recommendation="Restrict network ranges and storage ACLs to the required principals.",
                likelihood="medium",
                impact="high",
                likelihood_score=3,
                impact_score=4,
            )
    return findings


def scan_iac(root: Path, config: Config) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_files(root, config):
        text = read_text(path, config.max_file_bytes)
        if text is None:
            continue
        relative = path.relative_to(root.resolve()).as_posix()
        if relative.startswith(".github/workflows/") and path.suffix in {".yml", ".yaml"}:
            findings.extend(_workflow_findings(root, path, text))
        if path.name == "firebase.json":
            findings.extend(_firebase_findings(root, path))
        if path.suffix.lower() == ".html":
            findings.extend(_html_findings(root, path, text))
        if path.name == "main.js" and "VITE_FIREBASE_API_KEY" in text:
            _add(
                findings,
                rule_id="firebase-web-api-key",
                title="Firebase web API key is shipped to the browser",
                severity="low",
                exposure="production-runtime",
                category="auth",
                location=location(root, path),
                summary="The web config is public by design. Protection depends on key restrictions and security rules.",
                recommendation="Restrict the key by HTTP referrer and API in Google Cloud. Keep Firestore and Storage rules closed by default.",
                likelihood="medium",
                impact="low",
                likelihood_score=3,
                impact_score=2,
            )
        findings.extend(_docker_k8s_terraform(root, path, text))
    return findings

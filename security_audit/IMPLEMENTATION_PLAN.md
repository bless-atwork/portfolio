# Implementation plan

This is the plan that the audit system in this repository follows.

## Inventory first

1. Treat the configured root as the application repository. Record languages, frameworks, and dependency manifests.
2. Count other git checkouts under the home directory without reading their files. Editor caches and version-manager checkouts are classified and excluded. Their paths are not written into the report, so this portfolio does not become a catalogue of unrelated trees.
3. Record which of the preferred scanners are installed. Missing tools do not stop the built-in checks.

## Checks

Run, in order, and keep going if one scanner fails:

1. Secret patterns and sensitive filenames.
2. Source patterns for HTML sinks, dynamic code, shell execution, SQL concatenation, SSRF-shaped calls, path sinks, weak hashes, disabled TLS verification, JWT `none`, unsafe deserialisers, wildcard CORS, and web-storage tokens.
3. Prompt-injection markers. The marker text is not copied into the report.
4. GitHub Actions pin, permissions, pull-request secrets, and ignored step failures.
5. Firebase Hosting security headers, remote stylesheets, Docker, Kubernetes, and Terraform patterns when those files exist.
6. World-writable files.
7. Loopback ports for PostgreSQL, MySQL/MariaDB, SQL Server, MongoDB, Redis, and Elasticsearch, plus SQLite filenames.
8. `npm audit --package-lock-only`, including a production-tree pass.
9. Gitleaks, Trivy misconfig, and OSV Scanner when the binaries are installed and the relevant network policy allows them.

## Reporting

Write the daily Markdown and JSON reports, the dashboard, execution history, knowledge-base articles, ranked patterns, and the monthly trend note.

Compare finding ids with the previous JSON report. New, resolved, and recurring titles are listed. Resolved ids are appended to `knowledge_base/resolved.jsonl` once.

## Fixes that are safe to apply by hand

The auditor does not edit the application. Changes in this repository were applied separately and only where they do not rotate or rewrite production credentials:

- DOM APIs replace HTML-string rendering.
- Firebase Hosting sends a content security policy and the related browser headers.
- GitHub Actions are pinned to commit SHAs and token permissions are explicit.
- Preview builds no longer receive the web API keys. The hosting service account is still required to publish a preview, and that residual risk stays in the report.
- Vite is moved off the vulnerable 8.2.0–8.2.3 range when a patched release installs and the site still builds.

`npm audit fix --force` is not run. The suggested Firebase downgrade is a major downgrade and is not applied.

## Explicit non-goals

- No password spraying, default-credential login, or database queries.
- No production credential rotation.
- No exploit procedures, payloads, or proof-of-concept code in the report.
- No upload to Snyk unless `network.snyk` is turned on.
- No scan of editor plugin caches or the Node version-manager checkout.
- No claim that a closed port has safe grants, backups, or indexes. Those cannot be seen without a database session.

## Schedule

GitHub Actions at 02:00 UTC, and an opt-in local cron, systemd timer, or Windows task at 02:00 local time. See `security_audit/README.md`.

## Extension

New rules belong in `security_audit/rules/` or a new module under `security_audit/scanners/`. Each finding needs a stable `rule_id`, an environmental severity, an exposure, a recommendation, and a test that proves secret values do not reach the report.

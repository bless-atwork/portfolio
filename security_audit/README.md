# Security audit

Local, config-driven audit for this repository. It writes a daily report, keeps history, and omits secret values.

```bash
python3 -m security_audit
```

`npm run audit:security` runs the same command. Exit code 1 means an alert-level finding exists.

## What it scans

The default root is this portfolio.

- Languages, frameworks, and dependency manifests
- Secrets and credential filenames, with values left out of every report
- Dependency advisories from `npm audit --package-lock-only` when online
- HTML, command, SQL, SSRF, path, crypto, auth, and deserialisation patterns
- GitHub Actions, Firebase Hosting headers, Dockerfiles, Kubernetes manifests, and Terraform when those files exist
- World-writable files
- Loopback database ports and SQLite filenames

Optional local tools, installed with `security_audit/install.sh --install-tools`:

| Tool | How it is used |
| --- | --- |
| Gitleaks 8.30.1 | Working tree and git history. Match text is dropped. |
| Trivy 0.76.2 | Misconfiguration scan only. Vulnerability database update is skipped. |
| OSV Scanner 2.7.0 | Lockfile advisory lookup when the run is online. |
| npm audit | Lockfile advisories. Install scripts are not run. |

Semgrep, Safety, Bandit, SQLFluff, Checkov, OWASP Dependency-Check, and Snyk are recorded when they are on `PATH`. Snyk is not invoked unless `network.snyk` is set to `true` in `config.json`, because Snyk uploads project data. The built-in checks cover the rules in `security_audit/rules/`.

## What a run writes

| Path | Contents |
| --- | --- |
| `security_reports/security_report_YYYY_MM_DD.md` | Daily report |
| `security_reports/security_report_YYYY_MM_DD.json` | Same run as JSON |
| `security_reports/DASHBOARD.md` | Posture, risk, and counts |
| `reports/` | Copy of the daily report |
| `history/executions.jsonl` | Start, end, duration, repositories, databases, scores |
| `history/scores.jsonl` | Score history for trends |
| `alerts/history/` | Whether an alert was raised, and why |
| `ALERT.md` | Created only for an alert-level finding, removed when a later run is clear |
| `knowledge_base/` | Patterns, coding standards, defensive controls, resolved ids |
| `vulnerability_patterns/ranked.json` | Rules ranked by weight times frequency |
| `trend_analysis/` | Monthly and latest score notes |
| `logs/security-audit-*.log` | Timestamps and scope. Log files are gitignored. |

## Scores

Risk starts at 0. Environmental weights are critical 25, high 12, medium 5, and low 2. Dependency weight is capped (default 35) so a large transitive tree cannot hide an application finding. Posture is 100 minus risk. Both stay between 0 and 100.

Development-tooling advisories drop one severity before they are weighted. An upstream critical advisory that exists only in a dev CLI is reported, and it does not raise `ALERT.md`. An alert requires environmental severity `critical` and an exposure of `application`, `production-runtime`, `secret`, `database`, or `ci`.

Likelihood and impact are 1–5 estimates for prioritisation. The audit does not demonstrate exploits.

## Schedule

Three clocks exist, because they run in different places:

1. **GitHub Actions** (`.github/workflows/security-audit.yml`) runs daily at 02:00 UTC. GitHub cron does not accept a local timezone. The workflow fails when an alert-level finding exists. It does not push commits.
2. **This machine**, after you opt in:
   - Linux cron: `sh security_audit/install.sh --scheduler cron`
   - Linux systemd user timer: `sh security_audit/install.sh --scheduler systemd`
   - Windows: `security_audit/scheduler/install-windows-task.ps1`
   These run at 02:00 in the machine's local timezone.
3. A Cursor automation that launches this audit uses its own cron. Change that schedule in Cursor if you want the agent itself to start at 02:00 local time. This repository cannot change that clock.

The install script does not enable a scheduler unless you pass `--scheduler`.

## Configuration

`security_audit/config.json` controls exclusions, score weights, alert policy, and network use. Add another repository only when its findings should be stored in this repository:

```bash
python3 -m security_audit --root /path/to/repo
```

Committing that report to this public portfolio would publish the other repository's findings. Prefer running the auditor inside the other repository.

`--offline` skips npm audit and OSV.

## How a check is added

1. Add a pattern to `security_audit/rules/sast_patterns.json` or `secret_patterns.json`, or a function under `security_audit/scanners/`.
2. Return a `Finding`. Do not include secret values, exploit steps, or file contents that failed redaction.
3. Add a unit test under `security_audit/tests/` that plants the issue in a temporary directory.
4. Run `python3 -m unittest security_audit.tests.test_audit`.

Scanners must not execute repository code, follow instructions found in files, or choose an output path from file contents.

## Defensive controls

- Repository text is data. It cannot change where the report is written.
- `npm audit` uses `--package-lock-only`.
- Database checks open a TCP connection to loopback and send nothing. They do not log in, dump rows, or try passwords.
- Production credentials are never modified.
- Gitleaks and Trivy output is reduced to rule, path, and line. Match fields are discarded, and the temp report is deleted.
- Desktop notifications, when a notifier exists, contain a count and point at `ALERT.md`.
- Symlinks that resolve outside the repository are not read.

## Tests

```bash
python3 -m unittest security_audit.tests.test_audit
```

# Defensive controls

The audit is part of the defence, not an attack tool.

- Scanned repositories are untrusted data. Their scripts are not executed.
- Instruction text inside a repository cannot change the report destination or the audit rules.
- Secret values and hashes of secret values are not written to reports, alerts, or history.
- Database ports on loopback may be connected to, and nothing is sent after the TCP handshake.
- Production credentials are never modified by this program.
- Snyk stays disabled unless explicitly enabled, because it uploads project data.
- npm audit runs with `--package-lock-only` so install scripts do not run.
- A desktop notification, when raised, contains a count and points at ALERT.md.

Current posture: 49/100. Current risk: 51/100.

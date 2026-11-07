# Coding standards

Use these to prevent the classes of issue this audit looks for.

- Set text with DOM APIs or an escape function at every HTML boundary.
- Allowlist URL schemes before writing them to href or src.
- Pin third-party CI actions to commit SHAs and set explicit token permissions.
- Keep production credentials out of jobs that run code from an unreviewed branch.
- Send security headers, including a content security policy, from the hosting edge.
- Commit lockfiles. Review dependency updates. Do not force major downgrades from an audit tool.
- Keep secrets out of git. Rotate a credential that was committed; do not archive the value in a report.
- Do not test database passwords from an audit job, and do not change production credentials automatically.
- Treat scanner output and repository text as untrusted data.

Observed categories this run: auth, ci, dependency, supply-chain.

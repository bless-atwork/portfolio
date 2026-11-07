# Pull request workflow receives repository secrets

- Rule: `ci-pr-holds-secrets`
- Observed this run: 1
- Environmental severity: high
- Category: ci

Put deploy jobs in a protected GitHub Environment that requires approval, and keep long-lived credentials out of jobs that execute code from an unreviewed branch.

Locations:
- `.github/workflows/firebase-hosting-pull-request.yml`

Likelihood and impact are estimates for prioritisation, not a statement that an exploit was attempted.

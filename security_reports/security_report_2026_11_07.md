# Executive Summary

Security posture is **49/100** and risk is **51/100**. A higher posture is better. A higher risk means more weighted findings.

Run window: 2026-11-07T23:27:51+00:00 to 2026-11-07T23:27:56+00:00 (5.148 seconds).

Repositories scanned:
- portfolio — languages: Python, HTML, JavaScript, CSS; frameworks: Firebase, GSAP, Vite, Firebase Hosting.

Other git checkouts on this machine were counted and not read: editor cache 9, runtime managers 1, other 0. Their paths and contents are not copied into this report.

Scanners: trivy: available, invoked; semgrep: not installed; gitleaks: available, invoked; osv-scanner: available, invoked; dependency-check: not installed; safety: not installed; bandit: not installed; npm: available, invoked; snyk: not installed (not invoked; Snyk uploads project data and stays off unless network.snyk is true); sqlfluff: not installed; checkov: not installed.

This repository is a static site. An advisory in the production dependency tree still needs a reachability check before it is treated as a hosted-site incident.

No repository script, Makefile, or package lifecycle hook was executed. Secret values are omitted. Database checks did not log in, query data, or try passwords. Snyk is off because it uploads project data.

Upstream critical advisories adjusted for exposure: 1. Adjusted items stay in the daily report and do not raise ALERT.md.

# Critical Issues

No finding is rated critical for this project.

1 advisory keeps an upstream severity of critical and is rated lower here because it only affects development tooling.


# High Severity Issues

- **Pull request workflow receives repository secrets** (high, likelihood 3/5, impact 5/5)
  - Location: `.github/workflows/firebase-hosting-pull-request.yml`
  - Exposure: ci
  - A pull_request workflow in this repository receives secrets. A branch pushed to the same repository can change the job that runs. Fork pull requests do not receive repository secrets.
  - Fix: Put deploy jobs in a protected GitHub Environment that requires approval, and keep long-lived credentials out of jobs that execute code from an unreviewed branch.
- Dependency advisories at this severity: 3. See Vulnerable Dependencies.


# Medium Severity Issues

- Dependency advisories at this severity: 14. See Vulnerable Dependencies.


# Low Severity Issues

- **Remote stylesheet has no integrity attribute** (low, likelihood 1/5, impact 2/5)
  - Location: `index.html:22`
  - Exposure: production-runtime
  - A third-party stylesheet is loaded without subresource integrity.
  - Fix: Self-host the font CSS or pin it with integrity and crossorigin.
- **Firebase web API key is shipped to the browser** (low, likelihood 3/5, impact 2/5)
  - Location: `src/main.js`
  - Exposure: production-runtime
  - The web config is public by design. Protection depends on key restrictions and security rules.
  - Fix: Restrict the key by HTTP referrer and API in Google Cloud. Keep Firestore and Storage rules closed by default.
- Dependency advisories at this severity: 32. See Vulnerable Dependencies.


# Secrets Found

No secrets, private keys, tokens, or credential assignments were recorded.


# Vulnerable Dependencies

| Advisory | Environmental | Upstream | Exposure | Packages |
| --- | --- | --- | --- | --- |
| @grpc/grpc-js: In certain configurations, getAuthContext can return unauthorized certificates as though they were authorized | high | high | production-dependency-tree | @grpc/grpc-js |
| RE2JS: Quadratic-time denial of service in re2js lookbehind matching | high | high | production-dependency-tree | re2js |
| proxy-addr vulnerable to IP spoofing via IPv4-mapped IPv6 trust subnet | high | critical | development-tooling | proxy-addr |
| MCP TypeScript SDK: Experimental tasks were not tied to the session that created them | medium | high | development-tooling | @modelcontextprotocol/sdk |
| MCP TypeScript SDK: HTTP server transports and handlers did not limit request body size or JSON-RPC batch length | medium | high | development-tooling | @modelcontextprotocol/sdk |
| MCP TypeScript SDK: OAuth client could send credentials to an authorization server chosen by the MCP server | medium | high | development-tooling | @modelcontextprotocol/sdk |
| MCP TypeScript SDK: One HTTP request within the default size limit could exhaust server memory during validation | medium | high | development-tooling | @modelcontextprotocol/sdk |
| Zod can exhaust memory while validating oversized constrained collections | medium | high | development-tooling | zod |
| basic-ftp: Quadratic-time CPU denial of service in Client.list() Unix directory-listing parser (RE_LINE backtracking) | medium | high | development-tooling | basic-ftp |
| body-parser vulnerable to Denial of Service via trailing bytes after a compressed request body | medium | high | development-tooling | body-parser |
| brace-expansion: DoS via uncontrolled recursion in parseCommaParts causing stack exhaustion | medium | high | development-tooling | brace-expansion |
| brace-expansion: DoS via uncontrolled recursion on nested brace groups causing stack exhaustion | medium | high | development-tooling | brace-expansion |
| compression vulnerable to Denial of Service via memory leak on premature response close | medium | high | development-tooling | compression |
| source-map-js allows event-loop denial of service through indexed source-map section offsets | medium | high | development-tooling | source-map-js |
| undici vulnerable to Denial of Service via TLS 1.2 certificate-changing renegotiation | medium | high | development-tooling | undici |
| undici vulnerable to Denial of Service via unhandled error on excessive content-encodings | medium | high | development-tooling | undici |
| undici vulnerable to TLS certificate validation bypass via dropped tls options in Agent | medium | high | development-tooling | undici |
| @grpc/grpc-js: The server transmits some error messages thrown by method handlers to the client in status messages | low | low | production-dependency-tree | @grpc/grpc-js |
| @hono/node-server: `serveStatic` decodes the request path a second time, leading to bypass of middleware on static paths | low | medium | development-tooling | @hono/node-server |
| Glob: AbortSignal cancellation bypass allows post-timeout filesystem traversal | low | medium | development-tooling | glob |
| Hono: `serveStatic` decodes the request path a second time, leading to bypass of middleware on static paths | low | medium | development-tooling | hono |
| MCP TypeScript SDK: Server bearer authentication accepted tokens issued for another service | low | medium | development-tooling | @modelcontextprotocol/sdk |
| MCP TypeScript client SDK: HTTP client transports and OAuth requests followed cross-origin redirects and re-sent custom headers and request bodies | low | medium | development-tooling | @modelcontextprotocol/sdk |
| OpenTelemetry Core: Unbounded memory allocation in W3C Baggage propagation | low | medium | development-tooling | @opentelemetry/core |
| brace-expansion: Quadratic-time expansion of the `{a},b}` rewrite causes CPU denial of service | low | medium | development-tooling | brace-expansion |
| fast-uri vulnerable to URI scheme spoofing via percent-encoded scheme decoding | low | medium | development-tooling | fast-uri |
| fast-uri vulnerable to host confusion via unchecked WHATWG host canonicalization | low | medium | development-tooling | fast-uri |
| fast-uri vulnerable to improper path equivalence in relative reference normalization | low | low | development-tooling | fast-uri |
| fast-uri vulnerable to inconsistent host case normalization via percent-encoded octets | low | medium | development-tooling | fast-uri |
| fast-uri vulnerable to scheme injection via an unescaped first-segment colon in suffix references | low | low | development-tooling | fast-uri |
| ip-address: Address6 builds a parse diagnostic proportional to the input with no length bound, allowing a single long string to stall or crash the process | low | medium | development-tooling | ip-address |
| ip-address: Address6 matches a zone identifier in quadratic time ahead of its length limit, allowing a single long string to stall the process | low | medium | development-tooling | ip-address |
| ip-address: isInSubnet() and isHostInSubnet() compare addresses of different families as if they shared an address space, allowing an allowlist check to admit an address outside its range | low | medium | development-tooling | ip-address |
| minimatch has potential denial of service via globparts amplification | low | medium | development-tooling | minimatch |
| morgan vulnerable to Log Injection via unescaped double quote in quoted log fields | low | medium | development-tooling | morgan |
| node-csv: Prototype replacement still reachable via columns path | low | medium | development-tooling | csv-parse |
| node-re2: Out-of-bounds heap read in `replace`/`split` via a `Buffer` ending in a truncated multi-byte UTF-8 character → adjacent heap memory disclosed to JavaScript | low | medium | development-tooling | re2 |
| node-re2: String.prototype.replace(re2, template) aborts the Node process (uncatchable ToLocalChecked on empty MaybeLocal) when the result exceeds V8's max string length | low | medium | development-tooling | re2 |
| qs : qs.stringify with arrayFormat 'comma' throws an uncaught TypeError on array elements carrying a non-callable own toString (DoS) | low | medium | development-tooling | qs |
| qs array-limit bypass via bracket-key comma parsing | low | medium | development-tooling | qs |
| qs: Denial of Service via Attacker Controlled isBuffer | low | medium | development-tooling | qs |
| re2: Global `String.prototype.match` with an empty-matchable pattern never advances → infinite loop with unbounded native memory growth (DoS) | low | medium | development-tooling | re2 |
| re2: Out-of-bounds heap read in `exec`/`test`/`match` via attacker-influenced `lastIndex` on a non-ASCII subject → uncatchable process crash (DoS) | low | medium | development-tooling | re2 |
| stream-json has a prototype pollution issue: Assembler writes this.current[this.key] on plain objects | low | medium | development-tooling | stream-json |
| stream-json: JSONC parser and verifier re-scan the whole accumulated comment on every input chunk | low | medium | development-tooling | stream-json |
| stream-json: pick/ignore/filter/replace filters are O(depth²) on nested input — small crafted JSON blocks the event loop for seconds→minutes (DoS) | low | medium | development-tooling | stream-json |
| undici WebSocket client vulnerable to Denial of Service via unbounded automatic PONG buffering | low | medium | development-tooling | undici |
| undici vulnerable to Denial of Service via unbounded memory in the EventSource parser | low | medium | development-tooling | undici |
| uuid: Missing buffer bounds check in v3/v5/v6 when buf is provided | low | medium | development-tooling | uuid |


# Database Findings

- **postgresql** — not_listening. No local listener. Passwords, grants, backups, and indexes were not inspected.
- **mysql** — not_listening. No local listener. Passwords, grants, backups, and indexes were not inspected.
- **mariadb** — not_listening. No local listener. Passwords, grants, backups, and indexes were not inspected.
- **sqlserver** — not_listening. No local listener. Passwords, grants, backups, and indexes were not inspected.
- **mongodb** — not_listening. No local listener. Passwords, grants, backups, and indexes were not inspected.
- **redis** — not_listening. No local listener. Passwords, grants, backups, and indexes were not inspected.
- **elasticsearch** — not_listening. No local listener. Passwords, grants, backups, and indexes were not inspected.
- **sqlite** — not_found. No SQLite files were found in the scanned tree.

Password strength, anonymous login, grants, backups, indexes, and public exposure were not probed. The audit only checks loopback ports and whether a database file is present.


# Recommended Fixes

- Pull request workflow receives repository secrets: Put deploy jobs in a protected GitHub Environment that requires approval, and keep long-lived credentials out of jobs that execute code from an unreviewed branch.
- Firebase web API key is shipped to the browser: Restrict the key by HTTP referrer and API in Google Cloud. Keep Firestore and Storage rules closed by default.
- Remote stylesheet has no integrity attribute: Self-host the font CSS or pin it with integrity and crossorigin.
- Review the dependency table before upgrading. Do not run `npm audit fix --force` unattended, and do not downgrade Firebase to clear a transitive advisory.
- Keep this audit on the daily schedule and compare the next report with this baseline.

# Risk Score

Risk score: **51** / 100.
Security posture: **49** / 100.

Risk starts at 0. Each finding adds its environmental weight: critical 25, high 12, medium 5, low 2. Dependency weight is capped at 35. Development-tooling advisories drop one severity before weighting. Posture is 100 minus risk. Both scores stay between 0 and 100.

Dependency weight 170 (applied 35). Other weight 16.


# Audit History Comparison

Compared with `security_report_2026_11_07.json`.

New findings: 0.
Resolved findings: 0.
Recurring findings: 52.
Risk delta: 0.

Recurring:
- Remote stylesheet has no integrity attribute
- Firebase web API key is shipped to the browser
- Pull request workflow receives repository secrets
- @grpc/grpc-js: In certain configurations, getAuthContext can return unauthorized certificates as though they were authorized
- @grpc/grpc-js: The server transmits some error messages thrown by method handlers to the client in status messages
- @hono/node-server: `serveStatic` decodes the request path a second time, leading to bypass of middleware on static paths
- MCP TypeScript SDK: OAuth client could send credentials to an authorization server chosen by the MCP server
- MCP TypeScript SDK: Experimental tasks were not tied to the session that created them
- MCP TypeScript SDK: One HTTP request within the default size limit could exhaust server memory during validation
- MCP TypeScript SDK: Server bearer authentication accepted tokens issued for another service
- MCP TypeScript SDK: HTTP server transports and handlers did not limit request body size or JSON-RPC batch length
- MCP TypeScript client SDK: HTTP client transports and OAuth requests followed cross-origin redirects and re-sent custom headers and request bodies


# Defensive Controls

Repository content is data. This audit never executes it and never follows instructions found in it.
Reports store rule, path, and line. They do not store secret values, secret hashes, or query results.
Output stays inside this repository. Scanned files cannot choose a destination.
Optional scanners run as local programs. Their match fields are dropped before a finding is saved.
A critical alert writes ALERT.md and, when a desktop notifier exists, a count-only notification.

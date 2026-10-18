# Change review checklist

Source of truth for `sk-review` check IDs. A fast security review of **one change**: uncommitted work, staged
changes, a branch or a pull request, in any language. It asks one question: *does this change introduce or remove
risk?* It looks only at changed lines and their immediate context. Based on the OWASP Code Review Guide and the
Secure Code Review cheat sheet.

Findings from the specialist scanners keep **their own check IDs** (e.g. `INJ-SQL-001`, `AUTH-SESS-002`); the
`REVIEW-*` IDs below cover what is specific to reviewing a diff. `references/guide.md` explains each check.

Columns: **Mode** S = static. Severity is the default; adjust it to the actual change. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| REVIEW-AUTHZ-001 | New or changed endpoints, handlers, resolvers, jobs and agent tools require authentication and check object/tenant-level authorization | S | High | A01 | CWE-862 |
| REVIEW-INPUT-001 | New inputs (params, bodies, headers, files, messages, env) are validated: types, ranges, allow-lists, no mass assignment | S | Medium | A03 | CWE-20 |
| REVIEW-SINK-001 | New uses of dangerous sinks (SQL, shell, eval, templates, raw HTML, file paths, outbound URLs, redirects, deserialization, model output) use the safe API | S | High | A03 | CWE-74 |
| REVIEW-REMOVED-001 | The change does not remove or weaken an existing control (auth middleware, permission checks, validation, escaping, CSRF, rate limits, signature/TLS verification, limits, approvals) without an equivalent replacement | S | High | A04 | CWE-693 |
| REVIEW-SECRET-001 | No credentials, keys, tokens or private URLs are added in code, config, tests, fixtures or docs | S | High | A07 | CWE-798 |
| REVIEW-CONFIG-001 | Security configuration is not weakened (CORS, cookies, CSP/headers, debug modes, TLS, permissions, insecure defaults, feature flags) | S | Medium | A05 | CWE-16 |
| REVIEW-DEPS-001 | New or upgraded dependencies are necessary, from trusted publishers, correctly spelled (no typosquats), pinned/locked, without surprising install scripts, and free of known vulnerabilities | S | Medium | A06 | CWE-1104 |
| REVIEW-CRYPTO-001 | Changes to hashing, encryption, signing, tokens or randomness use vetted primitives and libraries with safe parameters | S | High | A02 | CWE-327 |
| REVIEW-DATA-001 | New data collected, stored, logged, returned or sent to third parties (including AI providers) is necessary and protected; no sensitive data in logs, errors or responses | S | Medium | A04 | CWE-200 |
| REVIEW-INFRA-001 | Changes to CI/CD, containers, IaC and agent/MCP configs keep least privilege and pinning (deep dive with the matching skill) | S | High | A05 | CWE-250 |
| REVIEW-ERROR-001 | New error handling fails closed and does not leak internals (stack traces, queries, paths) | S | Low | A04 | CWE-209 |
| REVIEW-TEST-001 | Security-relevant changes include tests: authorization negative cases, invalid input, and a regression test for any fixed vulnerability | S | Low | A04 | CWE-1059 |

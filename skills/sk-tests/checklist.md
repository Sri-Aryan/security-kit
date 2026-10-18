# Security test coverage checklist

Source of truth for `sk-tests` check IDs. Measures whether the project's **automated tests prove its security
controls work**, in any language and test framework, and generates the missing tests. A control without a negative
test is a control that silently breaks in the next refactor. Based on the OWASP Web Security Testing Guide, the OWASP
Authorization Testing Automation and Unit Testing cheat sheets. `references/guide.md` shows test patterns.

Columns: **Mode** S = static. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| TEST-AUTHN-001 | Every protected endpoint has a test proving an unauthenticated request is refused (401), and a test with an invalid/expired token or session | S | High | A07 | CWE-306 |
| TEST-AUTHZ-001 | Every endpoint that reads or changes an object by ID has a cross-user / cross-tenant test proving another user's object is refused (403/404) | S | High | A01 | CWE-639 |
| TEST-ROLE-001 | Admin-only and role-restricted operations have tests proving lower roles are refused (vertical escalation) | S | High | A01 | CWE-285 |
| TEST-VALID-001 | Endpoints that accept input have tests for invalid, missing, oversized and unexpected fields (400/422), including mass-assignment of privileged fields | S | Medium | A03 | CWE-20 |
| TEST-INJ-001 | Code that reaches interpreters (SQL, shell, templates, HTML, paths, URLs) has payload tests proving input is treated as data | S | Medium | A03 | CWE-74 |
| TEST-SESSION-001 | Login, logout, password reset, MFA and token refresh flows have tests for failure paths (wrong password, reused/expired token, logout invalidates the session) | S | Medium | A07 | CWE-613 |
| TEST-LIMIT-001 | Rate limits, quotas and size limits have tests proving they trigger (429/413) | S | Low | A04 | CWE-770 |
| TEST-ERR-001 | Error responses are tested to contain no stack traces, queries or internal details | S | Low | A05 | CWE-209 |
| TEST-REG-001 | Every fixed security finding has a regression test that fails on the vulnerable code | S | Medium | A04 | CWE-1059 |
| TEST-FIXTURE-001 | Test setup supports security tests: at least two users/tenants and multiple roles; auth is not globally mocked or bypassed in a way that hides access-control bugs | S | Medium | A04 | CWE-1059 |
| TEST-CI-001 | Security tests run automatically in CI on every change and failures block merging | S | Medium | A04 | CWE-1059 |

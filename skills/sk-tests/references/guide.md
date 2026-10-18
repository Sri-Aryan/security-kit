# Security test guide

Sources: OWASP Web Security Testing Guide, OWASP Authorization Testing Automation and Unit Testing cheat sheets.
Framework-neutral; write tests in the project's existing framework, style and helpers.

## The minimum set per endpoint

| Endpoint kind | Tests |
|---|---|
| Any protected endpoint | no credentials → 401 · invalid/expired token → 401 |
| Object by ID (`/orders/:id`, `?accountId=`) | user B requests user A's object → 403 or 404 (and nothing is changed) · same for another tenant |
| Role-restricted | regular user → 403 · lower role cannot change their own role/permissions |
| Accepts input | missing required field → 400/422 · wrong type · too long / too large · unknown field like `role`, `isAdmin`, `ownerId`, `price` is ignored or rejected |
| Reaches an interpreter | a payload (`' OR '1'='1`, `<i>sk</i>`, `../../etc/passwd`, `{"$ne": null}`, `{{7*7}}`) is stored/returned as plain data or rejected |
| Rate-limited | N+1 attempts → 429 |

Negative tests must assert **both** the status and the absence of the side effect (row unchanged, no email sent,
response body contains no data from the other user).

## Fixtures (TEST-FIXTURE-001)

Create two users in two tenants (A, B) and one admin with the project's factories/seeds. Use real authentication
in endpoint tests (log in, or sign tokens with the test key), not a global mock that makes every request admin. A
table-driven test (endpoint × role → expected status) covers many routes cheaply:

```text
cases = [ (GET  /api/orders/{A.order},  anon → 401, B → 404, A → 200, admin → 200),
          (POST /api/admin/users,       anon → 401, A → 403, admin → 201) ]
for each case and each actor: request as actor, assert status
```

## Regression tests (TEST-REG-001)

For each finding in a SecurityKit report (`regressionTest` field), write the test first, see it fail on the vulnerable
code, then fix. Name it after the check ID (e.g. `test_INJ_SQL_001_order_search_parameterized`) so the link is visible.

## CI (TEST-CI-001)

Security tests are ordinary tests: same runner, same CI job, required to pass before merge. Don't hide them in a
manual or nightly job.

# API security checklist (PLACEHOLDER)

> **PLACEHOLDER — NOT THE REAL CHECKLIST.** The real source of truth is `api-security-checks.md`
> (~130 checks), which must be copied here unchanged. This file only lists the check IDs that the
> Semgrep rules and the example app reference, so tests and the skill run end to end.
> `tests/test_check_ids.py` fails loudly if any referenced ID is missing from the real file.

Columns: **Mode** S = static, D = dynamic, S+D = both. OWASP = OWASP API Security Top 10 (2023).

## Inventory (INV)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| API-INV-001 | Every endpoint is inventoried with method, path, handler and auth status | S | Medium | API9 | CWE-1059 |
| API-INV-002 | Endpoints in code match the OpenAPI spec (no undocumented or stale routes) | S | Low | API9 | CWE-1059 |

## Authentication (AUTHN)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| API-AUTHN-001 | Non-public endpoints require authentication middleware | S+D | High | API2 | CWE-306 |
| API-AUTHN-002 | JWTs are signature-verified (no decode-without-verify) | S | Critical | API2 | CWE-347 |
| API-AUTHN-003 | JWT algorithms are pinned; `none` is rejected | S+D | Critical | API2 | CWE-327 |
| API-AUTHN-004 | Login and credential endpoints are rate limited / lock out | S+D | High | API4 | CWE-307 |

## Authorization (AUTHZ)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| API-AUTHZ-001 | Object-level authorization: resources fetched by ID are checked against the caller (IDOR/BOLA) | S+D | Critical | API1 | CWE-639 |
| API-AUTHZ-002 | Function-level authorization: admin/privileged routes check role | S+D | High | API5 | CWE-285 |
| API-AUTHZ-003 | Property-level authorization: request bodies cannot set protected fields (mass assignment) | S+D | High | API3 | CWE-915 |

## Input validation and injection (INJ)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| API-INJ-001 | SQL queries are parameterised (no string concatenation/interpolation of input) | S | Critical | API8 | CWE-89 |
| API-INJ-002 | NoSQL queries do not accept raw operator objects from input | S | High | API8 | CWE-943 |
| API-INJ-003 | No OS command built from input | S | Critical | API8 | CWE-78 |
| API-INJ-004 | File paths from input are confined to an allowed directory | S | High | API8 | CWE-22 |
| API-INJ-005 | Request bodies are schema-validated (types, lengths, unknown fields) | S+D | Medium | API8 | CWE-20 |

## Server-side request forgery (SSRF)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| API-SSRF-001 | User-supplied URLs are not fetched without an allow-list | S+D | High | API7 | CWE-918 |

## Data exposure (DATA)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| API-DATA-001 | Responses do not include sensitive fields (password hashes, tokens, internal IDs) | S+D | High | API3 | CWE-213 |

## Errors (ERR)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| API-ERR-001 | Errors return generic messages; no stack traces or internals in responses | S+D | Medium | API8 | CWE-209 |
| API-ERR-002 | Correct status codes (401 vs 403 vs 404 vs 422 vs 500) | D | Low | API8 | CWE-703 |

## Configuration (CFG)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| API-CFG-001 | CORS does not combine wildcard / reflected origin with credentials | S+D | High | API8 | CWE-942 |
| API-CFG-002 | Debug mode is off outside development | S | Medium | API8 | CWE-489 |
| API-CFG-003 | TLS certificate verification is not disabled | S | High | API8 | CWE-295 |
| API-CFG-004 | Security headers are set (HSTS, nosniff, frame options) | D | Low | API8 | CWE-693 |

## Secrets (SECRET)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| API-SECRET-001 | No hardcoded secrets, keys or signing secrets in source | S | High | API8 | CWE-798 |

## Rate limiting (RATE)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| API-RATE-001 | Expensive or bulk endpoints have rate limits and pagination caps | S+D | Medium | API4 | CWE-770 |

## Tests (TEST)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| API-TEST-001 | Auth and ownership have automated tests | S | Low | API1 | CWE-1125 |

# REST security checklist

Source of truth for `sk-rest` check IDs. Covers the HTTP-level hygiene of REST APIs in any language or
framework, following the OWASP REST Security Cheat Sheet section by section (HTTPS, access control, JWT, API
keys, HTTP methods, out-of-order execution, input validation, content types, management endpoints, error
handling, audit logs, security headers, CORS, sensitive data in URLs, status codes) plus the REST Assessment
Cheat Sheet. `sk-api` audits API business logic in depth (IDOR, mass assignment, injection, SSRF) with Semgrep and
dynamic tests; this skill is the protocol-level baseline. `references/guide.md` explains each check.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP API Top 10 2023 / Top 10 2021.

## Transport and access (TLS / ACCESS)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| REST-TLS-001 | Only HTTPS endpoints are exposed (HTTP redirects or is refused); mutual TLS for highly privileged service-to-service APIs | S+D | High | A02 | CWE-319 |
| REST-ACCESS-001 | Every non-public endpoint enforces authentication and authorization locally, deny-by-default | S+D | Critical | API5 | CWE-284 |
| REST-ACCESS-002 | Every endpoint that addresses a record by ID checks the caller may access that record (IDOR/BOLA) | S+D | Critical | API1 | CWE-639 |

## Credentials (JWT / KEY)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| REST-JWT-001 | JWTs are verified with a pinned algorithm (never `none`), and `iss`, `aud`, `exp` (and `nbf`) are validated; logout denylists the `jti` until expiry | S | High | API2 | CWE-347 |
| REST-KEY-001 | API keys are required on every protected request, sent in headers, revocable, rate-limited (429), and not the only control for sensitive resources | S | Medium | API2 | CWE-287 |

## Methods and workflow (METHOD / FLOW)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| REST-METHOD-001 | Each endpoint allows an explicit list of HTTP methods (others → 405), authorizes per method, and is not exposed to verb tampering (catch-all handlers, method-override headers, method-specific security constraints) | S+D | Medium | API5 | CWE-650 |
| REST-FLOW-001 | Multi-step workflows validate state transitions server-side on every request; clients cannot skip or reorder steps or set state directly | S | High | API6 | CWE-841 |

## Input (INPUT)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| REST-INPUT-001 | All input is validated by type, length, range and format with a schema; unexpected fields and content are rejected; validation failures are logged | S | High | API8 | CWE-20 |
| REST-INPUT-002 | Request size is limited and oversized requests are rejected with 413 | S+D | Medium | API4 | CWE-770 |
| REST-INPUT-003 | Parsers are secure: XML external entities disabled, no unsafe deserialization of request bodies | S | High | A05 | CWE-611 |

## Content types (CTYPE)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| REST-CTYPE-001 | Requests with bodies must carry a supported `Content-Type`; others are rejected with 415 | S+D | Medium | API8 | CWE-436 |
| REST-CTYPE-002 | Responses declare the `Content-Type` that matches the body (e.g. `application/json`); the `Accept` header is never copied into `Content-Type` | S+D | Medium | API8 | CWE-116 |

## Exposure and errors (MGMT / ERR / URL)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| REST-MGMT-001 | Management, debug and metrics endpoints (actuator, pprof, admin consoles, debug toolbars) are not exposed to the internet and require strong authentication | S+D | High | API9 | CWE-306 |
| REST-ERR-001 | Errors return generic messages without stack traces, exception details or internal identifiers | S+D | Medium | API8 | CWE-209 |
| REST-URL-001 | Passwords, tokens, API keys and personal data are never placed in URLs; GET requests carry them in headers | S | High | API8 | CWE-598 |

## Headers and CORS (HDR / CORS)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| REST-HDR-001 | API responses set `Cache-Control: no-store`, `Content-Security-Policy: frame-ancestors 'none'`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (and ideally `Referrer-Policy: no-referrer`); framework version headers are removed | S+D | Medium | API8 | CWE-693 |
| REST-CORS-001 | CORS is off unless cross-origin calls are needed; origins are an explicit allow-list; wildcard or reflected origins are never combined with credentials | S+D | High | API8 | CWE-942 |

## Logging, status codes, rate limits (AUDIT / STATUS / RATE)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| REST-AUDIT-001 | Security events (authentication failures, token validation errors, permission denials, validation failures) are audit-logged, with log data sanitized against injection | S | Medium | A09 | CWE-778 |
| REST-STATUS-001 | Status codes are correct and consistent (401 vs 403 vs 404, 405, 406, 413, 415, 429; errors never returned as 200) | S+D | Low | API8 | CWE-703 |
| REST-RATE-001 | Endpoints are rate-limited per client and respond 429 when exceeded | S+D | Medium | API4 | CWE-770 |

## Tests (TEST)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| REST-TEST-001 | Tests cover unauthenticated and cross-user access, disallowed methods (405), wrong content types (415), oversized bodies (413), error bodies without stack traces, and security headers | S | Low | API8 | CWE-1125 |

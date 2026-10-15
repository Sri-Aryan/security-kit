# OpenAPI contract security checklist

Source of truth for `sk-openapi` check IDs. Checks describe **concepts** about an API contract (OpenAPI 3.x
or Swagger 2.0, in any language or framework): does the contract match the code, does it declare
security correctly, and does it constrain input and output. `references/guide.md` explains each one.

Columns: **Mode** S = static, D = dynamic (fetch a live spec / check an exposed docs UI), S+D = both.
OWASP = OWASP API Security Top 10 (2023).

## Inventory and drift (INV / DRIFT)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| OAS-INV-001 | A machine-readable spec exists (file or generated at runtime), parses, and is identified as the contract | S+D | Medium | API9 | CWE-1059 |
| OAS-DRIFT-001 | No undocumented endpoints: every route in code appears in the spec | S | High | API9 | CWE-1059 |
| OAS-DRIFT-002 | No stale entries: every operation in the spec still exists in code (or is intentionally served elsewhere) | S | Medium | API9 | CWE-1059 |
| OAS-DRIFT-003 | Methods and path parameters match between spec and code for the same path | S | Medium | API9 | CWE-1059 |
| OAS-DRIFT-004 | Operations marked `deprecated` are scheduled for removal and not silently kept serving | S | Medium | API9 | CWE-1059 |
| OAS-DRIFT-005 | Old API versions / base paths still mounted in code are documented and protected like current ones | S | High | API9 | CWE-1059 |

## Authentication and authorization (AUTH)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| OAS-AUTH-001 | Security schemes are defined and a global security requirement applies by default | S | High | API2 | CWE-306 |
| OAS-AUTH-002 | Operations that opt out (`security: []`) or allow anonymous (`{}` in the list) are intentionally public, especially write methods | S | High | API2 | CWE-306 |
| OAS-AUTH-003 | Spec and code agree: operations the spec marks as secured are protected in code (and vice versa) | S | High | API2 | CWE-306 |
| OAS-AUTH-004 | No weak schemes: HTTP Basic over the internet, API keys in the query string, OAuth2 implicit or password flows | S | Medium | API2 | CWE-598 |
| OAS-AUTH-005 | Privileged operations declare the scopes/roles they require | S | Low | API5 | CWE-285 |
| OAS-AUTH-006 | Secured operations document 401/403 responses | S | Low | API2 | CWE-306 |

## Data contracts (DATA)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| OAS-DATA-001 | Write request bodies are closed objects (`additionalProperties: false`), so unknown fields are rejected | S | Medium | API3 | CWE-915 |
| OAS-DATA-002 | Server-controlled fields (id, role, owner, tenant, createdAt, balance, verified) are `readOnly` or absent from write schemas | S | Medium | API3 | CWE-915 |
| OAS-DATA-003 | Response schemas do not expose sensitive properties (passwords, secrets, tokens, SSNs, card data) | S | High | API3 | CWE-213 |
| OAS-DATA-004 | Inputs are constrained: strings have `maxLength`/`pattern`/`format`/`enum`, numbers have bounds | S | Low | API8 | CWE-20 |
| OAS-DATA-005 | Error responses use a generic schema with no stack trace / exception / internal fields | S | Low | API8 | CWE-209 |

## Resource limits (LIMIT)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| OAS-LIMIT-001 | Arrays declare `maxItems`; pagination parameters (limit, pageSize, per_page, first) declare a `maximum` | S | Medium | API4 | CWE-770 |
| OAS-LIMIT-002 | File uploads declare size limits and allowed content types | S | Medium | API4 | CWE-400 |
| OAS-LIMIT-003 | Rate-limited operations document 429 responses | S | Low | API4 | CWE-770 |

## Exposure (EXPO)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| OAS-EXPO-001 | `servers` / `host` use HTTPS only and do not reveal internal, staging or localhost hosts in a public spec | S | Medium | API8 | CWE-319 |
| OAS-EXPO-002 | Examples and defaults contain no real secrets, tokens or personal data | S | Medium | API8 | CWE-798 |
| OAS-EXPO-003 | Spec and docs UI exposure is intentional: internal/admin specs and Swagger UI are not public in production | S+D | Low | API9 | CWE-200 |

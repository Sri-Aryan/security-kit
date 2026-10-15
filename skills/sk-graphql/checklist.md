# GraphQL security checklist

Source of truth for `sk-graphql` check IDs. Checks describe **concepts**, not frameworks: each one
applies to any GraphQL server (JavaScript, Python, Go, Java/Kotlin, .NET, Ruby, PHP, Elixir, Rust).
`references/guide.md` explains how to verify and fix each one in any stack.

Columns: **Mode** S = static (read code/config), D = dynamic (probe a running endpoint), S+D = both.
OWASP = OWASP API Security Top 10 (2023).

## Surface (INV)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| GQL-INV-001 | Every GraphQL endpoint is identified, including secondary, legacy, versioned and internal ones (e.g. `/graphql`, `/v1/graphql`, `/api/graphql`, admin or gateway endpoints) | S+D | Medium | API9 | CWE-1059 |
| GQL-INV-002 | Every query, mutation and subscription is listed with its resolver location | S | Low | API9 | CWE-1059 |

## Introspection and discovery (INTRO)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| GQL-INTRO-001 | Introspection is disabled in production, or limited to authenticated internal users | S+D | Medium | API8 | CWE-200 |
| GQL-INTRO-002 | Field suggestions ("Did you mean …?") are disabled in production, so the schema cannot be rebuilt by guessing | D | Low | API8 | CWE-200 |
| GQL-INTRO-003 | Interactive IDEs (GraphiQL, Playground, Sandbox, landing pages) are not served in production | S+D | Low | API8 | CWE-489 |

## Resource limits (DOS)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| GQL-DOS-001 | A maximum query depth is enforced before execution | S+D | High | API4 | CWE-770 |
| GQL-DOS-002 | A query cost / complexity limit is enforced before execution (accounts for list multipliers) | S+D | High | API4 | CWE-770 |
| GQL-DOS-003 | Every list field is paginated and the page size has an enforced maximum | S+D | Medium | API4 | CWE-770 |
| GQL-DOS-004 | Request body size, token count, execution timeout and directive/field-duplication limits are set | S | Medium | API4 | CWE-400 |
| GQL-DOS-005 | Standard validation rules are not disabled (fragment cycles, unknown fields, overlapping fields) | S | Medium | API4 | CWE-674 |

## Batching (BATCH)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| GQL-BATCH-001 | Array batching (a JSON list of operations in one request) is disabled or capped | S+D | Medium | API4 | CWE-770 |
| GQL-BATCH-002 | Alias batching is limited, so one request cannot run the same field hundreds of times (e.g. brute-forcing a login or OTP mutation) | S+D | High | API4 | CWE-307 |
| GQL-BATCH-003 | Rate limits count operations / root fields / cost, not only HTTP requests | S | Medium | API4 | CWE-770 |

## Authentication (AUTHN)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| GQL-AUTHN-001 | The caller is authenticated when the request context is built; operations that should be public are explicitly marked | S+D | High | API2 | CWE-306 |
| GQL-AUTHN-002 | Subscriptions / WebSocket connections authenticate on connect and re-check authorization per event | S | High | API2 | CWE-306 |

## Authorization (AUTHZ)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| GQL-AUTHZ-001 | Object-level authorization: resolvers that load an object by ID check that the caller may access it | S+D | Critical | API1 | CWE-639 |
| GQL-AUTHZ-002 | Field-level authorization: sensitive fields (PII, secrets, roles, internal data) are guarded on the field itself or in the data layer | S+D | High | API3 | CWE-285 |
| GQL-AUTHZ-003 | Function-level authorization: privileged mutations (delete, role change, refund, impersonate) check the caller's role | S+D | High | API5 | CWE-285 |
| GQL-AUTHZ-004 | Generic lookups (`node(id:)`, `nodes(ids:)`, federation `_entities`) enforce the same authorization as typed queries | S+D | High | API1 | CWE-639 |
| GQL-AUTHZ-005 | Input types cannot set protected fields (role, owner, tenant, balance, verified flags) | S | High | API3 | CWE-915 |
| GQL-AUTHZ-006 | Authorization cannot be bypassed through an alternate path: every parent field that returns a sensitive type applies the same rule | S | High | API1 | CWE-863 |

## Injection and input (INJ)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| GQL-INJ-001 | Resolver arguments never reach SQL, NoSQL, shell, template or file paths without parameterisation or validation | S | Critical | API8 | CWE-89 |
| GQL-INJ-002 | Custom scalars (Email, URL, JSON, Upload) validate and bound their input | S | Medium | API8 | CWE-20 |
| GQL-INJ-003 | Resolvers that fetch URLs taken from arguments are protected against SSRF | S | High | API7 | CWE-918 |

## Errors (ERR)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| GQL-ERR-001 | Errors are masked in production: no stack traces, SQL, internal paths or exception messages in `errors[]` | S+D | Medium | API8 | CWE-209 |

## Transport and CSRF (CSRF)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| GQL-CSRF-001 | With cookie-based auth, operations cannot be triggered cross-site: mutations are rejected over GET and "simple" content types (`text/plain`, form-encoded) are rejected or a CSRF token / preflight-forcing header is required | S+D | Medium | API8 | CWE-352 |

## Architecture (ARCH)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| GQL-ARCH-001 | Federated subgraphs / internal GraphQL services are reachable only through the gateway; `_service` and `_entities` are not exposed publicly | S+D | High | API8 | CWE-284 |
| GQL-ARCH-002 | First-party clients use persisted queries / an operation allow-list where feasible | S | Low | API4 | CWE-770 |

## Tests (TEST)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| GQL-TEST-001 | Automated tests cover authorization of sensitive fields and objects, and the depth/cost/batching limits | S | Low | API1 | CWE-1125 |

# Database security checklist

Source of truth for `sk-database` check IDs. Covers how the application talks to its data stores (SQL and
NoSQL, ORMs and raw drivers) and how those stores are exposed, authenticated and configured, in any language.
Based on the OWASP Database Security, SQL Injection Prevention, Query Parameterization and NoSQL Security
cheat sheets. `references/guide.md` explains each check.

Columns: **Mode** S = static. OWASP = OWASP Top 10 2021 / API Top 10 2023.

## Query construction (QUERY / NOSQL)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DB-QUERY-001 | Every query uses bound parameters (prepared statements, ORM bindings); no SQL built by concatenation, formatting or interpolation | S | Critical | A03 | CWE-89 |
| DB-QUERY-002 | Dynamic identifiers (table, column, `ORDER BY`, direction) come from an allow-list, never from input | S | High | A03 | CWE-89 |
| DB-QUERY-003 | ORM escape hatches (raw/literal/unsafe APIs) are used only with bound parameters | S | High | A03 | CWE-89 |
| DB-QUERY-004 | Stored procedures and DB-side code do not build dynamic SQL from parameters (`EXEC`, `sp_executesql`, `EXECUTE format()` with concatenation) | S | High | A03 | CWE-89 |
| DB-NOSQL-001 | NoSQL queries reject operator objects from input and avoid server-side JavaScript (`$where`, `mapReduce`, `$function`, Redis `EVAL` with input) | S | High | A03 | CWE-943 |

## Data access logic (SCOPE / TXN / EXPOSE)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DB-SCOPE-001 | Queries for user-owned data are scoped by owner/tenant in the query itself (row-level authorization) | S | High | API1 | CWE-639 |
| DB-SCOPE-002 | Result sets are bounded (pagination with a maximum; no unbounded `findAll` on request paths) | S | Medium | API4 | CWE-770 |
| DB-SCOPE-003 | Bulk update/delete operations cannot run with an empty filter | S | High | A04 | CWE-20 |
| DB-TXN-001 | Multi-step state changes (balances, stock, unique claims) run in transactions with locking or atomic updates | S | High | A04 | CWE-362 |
| DB-EXPOSE-001 | Queries select only needed columns; whole rows/models are not returned to clients | S | Medium | API3 | CWE-213 |

## Exposure and transport (NET / TLS)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DB-NET-001 | Databases and caches are not reachable from the internet: bound to localhost/private networks, ports not published, firewalled | S | High | A05 | CWE-668 |
| DB-NET-002 | Database admin tools (phpMyAdmin, pgAdmin, Adminer, Mongo Express, Redis Commander, Kibana) are not publicly exposed and require authentication | S | High | A05 | CWE-306 |
| DB-TLS-001 | Connections use TLS 1.2+ and verify the server certificate (no `sslmode=disable`, `rejectUnauthorized: false`, `TrustServerCertificate=true`) | S | High | A02 | CWE-319 |

## Authentication, credentials, privileges (AUTH / CRED / PRIV)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DB-AUTH-001 | Every data store requires authentication (no unauthenticated Redis, MongoDB, Elasticsearch, Memcached, trust auth) | S | Critical | A07 | CWE-306 |
| DB-AUTH-002 | Database accounts use strong, unique credentials per application/service; no default or empty passwords | S | High | A07 | CWE-1392 |
| DB-CRED-001 | Database credentials are not in source code or committed config; they come from the environment or a secret manager | S | High | A07 | CWE-798 |
| DB-PRIV-001 | The application connects with a least-privilege account (not root/sa/postgres/SYS/admin, not the database owner), with separate accounts per environment | S | High | A01 | CWE-250 |

## Hardening and lifecycle (HARD / DATA / BACKUP)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DB-HARD-001 | Dangerous database features are disabled (`xp_cmdshell`, CLR, MySQL `FILE`/`LOCAL INFILE`, `COPY … PROGRAM`, server-side JS) | S | High | A05 | CWE-250 |
| DB-HARD-002 | Schema auto-sync / drop / auto-migrate on start is disabled in production | S | High | A05 | CWE-665 |
| DB-DATA-001 | Sensitive columns (tokens, keys, PII, card data) are encrypted or hashed at rest | S | Medium | A02 | CWE-311 |
| DB-BACKUP-001 | Backups and dumps are encrypted, access-controlled and never committed to the repository | S | High | A05 | CWE-530 |

## Errors and logging (ERR / LOG)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DB-ERR-001 | Database errors (SQL text, constraint names, driver messages) are not returned to clients | S | Medium | A05 | CWE-209 |
| DB-LOG-001 | Query logging with bound values is disabled in production (PII and secrets end up in logs) | S | Medium | A09 | CWE-532 |

## Tests (TEST)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DB-TEST-001 | Tests cover injection payloads on query parameters, cross-tenant/owner access, and concurrent updates of critical rows | S | Low | A03 | CWE-1125 |

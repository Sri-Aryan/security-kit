# Database security guide: how to verify and fix each concept

Sources: OWASP Database Security, SQL Injection Prevention, Query Parameterization and NoSQL Security cheat
sheets. Two halves, the same in every stack:
1. **The code's side**: how queries are built (parameterised or not), whose rows they touch (scoping), how
   much they return, and whether concurrent requests can corrupt state.
2. **The store's side**: who can reach it (network), how they prove who they are (auth, TLS), what they may do
   (privileges), and which dangerous features are switched on.

---

## Query construction (DB-QUERY-*, DB-NOSQL-001)

**Rule:** data goes into queries only as bound parameters. The query text is a constant.

| Stack | Safe | Unsafe |
|---|---|---|
| node-postgres / mysql2 | `query('… WHERE id = $1', [id])` | `` query(`… WHERE id = ${id}`) `` |
| Prisma | `` $queryRaw`… ${id}` `` (tagged) | `$queryRawUnsafe('…' + id)` |
| Sequelize / Knex | `replacements`, `bind`, `where({id})`, `raw('…?', [id])` | `query('…' + id)`, `literal(input)` |
| Python DB-API / SQLAlchemy | `execute('… %s', (id,))`, `text('… :id')` + params | f-strings, `%` or `.format` into SQL |
| Django | ORM, `raw('… %s', [id])` | `raw(f'…')`, `extra(where=[input])` |
| JDBC / JPA | `PreparedStatement` `?`, named params | `createStatement().executeQuery("…" + x)`, `createQuery("…" + x)` |
| Go database/sql / GORM | `Query("… $1", id)`, `Where("id = ?", id)` | `fmt.Sprintf` into SQL, `Raw(…+…)` |
| EF Core | `FromSqlInterpolated($"…{id}")` | `FromSqlRaw($"…{id}")` |
| Rails | `where(id: id)`, `where('id = ?', id)` | `where("id = #{id}")`, `find_by_sql` with interpolation |

Identifiers (`ORDER BY` column, table names, sort direction) cannot be parameters: map input through an
allow-list (`{"newest": "created_at DESC"}`). Stored procedures must not build SQL from parameters with
`EXEC(@sql)`; use `sp_executesql` with parameters or `format('%I', …)` plus `USING`.

NoSQL: a JSON body like `{"password": {"$ne": null}}` turns a value into an operator. Cast to string, use
`$eq`, enable the driver's filter sanitising (`sanitizeFilter`, `express-mongo-sanitize`), and do not use `$where`,
`mapReduce` or `$function` with input. Redis `EVAL`: pass keys and arguments, never build the script.

## Data access logic (DB-SCOPE-*, DB-TXN-001, DB-EXPOSE-001)

- **Scope in the query**: `WHERE id = $1 AND owner_id = $2` (or tenant ID), or a central repository layer /
  row-level security policy that adds it. Loading by ID and checking later is fine only if every path checks.
- **Bound results**: every list endpoint has a default and maximum page size.
- **Bulk operations**: `deleteMany({})`, `UPDATE t SET …` without `WHERE` should be impossible from request
  paths; require a non-empty filter.
- **Concurrency**: read-then-write of balances, stock, seats or "first claim wins" needs a transaction with
  `SELECT … FOR UPDATE`, an atomic update (`UPDATE … SET balance = balance - $1 WHERE balance >= $1`), or
  optimistic locking (version column). Otherwise two requests double-spend.
- **Columns**: select what you return; never serialise whole model rows to clients.

## Exposure and transport (DB-NET-*, DB-TLS-001)

Databases live on private networks, bound to localhost or an internal interface, never published with
`-p 5432:5432` (Docker bypasses host firewalls; use `127.0.0.1:5432:5432`). Admin UIs are not internet-facing.
Thick clients never talk to the database directly; route through an API. Every connection that crosses a
network uses TLS 1.2+ **and** verifies the server certificate (`sslmode=verify-full`, CA bundle configured).

## Authentication, credentials, privileges (DB-AUTH-*, DB-CRED-001, DB-PRIV-001)

Authentication on every store (Redis `requirepass`/ACLs, MongoDB auth, Elasticsearch security), no `trust`
lines in `pg_hba.conf`. One account per application and environment, strong generated passwords from a secret
manager, never in code. The application account is not root/sa/postgres/SYS, does not own the schema, has only
the rights it uses (typically SELECT/INSERT/UPDATE/DELETE on its tables), and runs migrations with a separate
account. Review and remove unused accounts.

## Hardening and lifecycle (DB-HARD-*, DB-DATA-001, DB-BACKUP-001)

Disable `xp_cmdshell`, CLR, OLE Automation (SQL Server); revoke `FILE` and disable `local_infile` (MySQL);
restrict `COPY … PROGRAM` to superusers (PostgreSQL); disable server-side JavaScript (MongoDB). Remove default
accounts and sample databases. No `sync({force: true})`, `synchronize: true`, `ddl-auto=update/create` or
`drop_all()` in production. Run versioned migrations instead. Encrypt sensitive columns (application-level or
column encryption) and hash tokens. Backups encrypted, access-controlled, tested, and never in the repository.

## Errors and logging (DB-ERR-001, DB-LOG-001)

Return generic errors with a correlation ID; log the driver error server-side. Turn off SQL logging with bound
values in production (`logging: false`, `echo=False`, no `EnableSensitiveDataLogging`).

## Test ideas (DB-TEST-001)

Send `' OR '1'='1`, `1;--`, `{"$ne":null}` to each query parameter and expect 400 or no extra rows; user B
requests user A's record; fire 20 concurrent withdrawals against one balance and check the final value.

# vulnerable-api: planted issues (answer key)

A small Express API with deliberate vulnerabilities, used to test SecurityKit's route discovery,
Semgrep rules and the `/sk-api` skill end to end. **Do not deploy it.**

> Demoing `/sk-api` on this app? Move this file out of the folder first so the agent is not primed
> by the answer key.

Run it (Node 22.5+ for the SQLite-backed product routes):

```
cd examples/vulnerable-api
npm install
npm start          # http://localhost:3000
```

Test accounts: `admin@example.test / admin-pass`, `alice@example.test / alice-pass`,
`bob@example.test / bob-pass` (get a token from `POST /api/auth/login`).

## Planted issues

`tests/test_detection.py` parses this table. **Anchor** is a unique code fragment on the vulnerable
line. **Detector** is `semgrep:<rule-id>` for issues the rules must catch statically, or `agent` for
issues that need the agent's reasoning (no static rule).

| # | Check ID | Planted issue | File | Anchor | Detector |
|---|---|---|---|---|---|
| 1 | API-AUTHZ-001 | IDOR: any logged-in user can read any order by ID (`GET /api/orders/:id`) | routes/orders.js | `Orders.findOne({ id: Number(req.params.id) })` | semgrep:sk-express-idor-param-lookup-without-user |
| 2 | API-AUTHZ-003 | Mass assignment: `POST /api/auth/register` accepts `"role": "admin"` from the body | routes/auth.js | `Users.create({ role: 'user', ...req.body })` | semgrep:sk-mass-assignment-js |
| 3 | API-AUTHN-002 | `GET /api/profile` trusts `jwt.decode()` (no signature check), so any forged token works | middleware/auth.js | `jwt.decode(token)` | semgrep:sk-jwt-decode-without-verify-js |
| 4 | API-INJ-001 | SQL injection via string concatenation in `GET /api/products/search?q=` | routes/products.js | `WHERE name LIKE '%" + req.query.q` | semgrep:sk-sql-injection-js |
| 5 | API-AUTHN-004 | No rate limiting or lockout on `POST /api/auth/login` | routes/auth.js | `router.post('/login'` | semgrep:sk-login-without-rate-limit-express |
| 6 | API-ERR-001 | Global error handler returns `err.stack` to the client | server.js | `stack: err.stack` | semgrep:sk-stack-trace-in-response-js |
| 7 | API-CFG-001 | CORS reflects any origin with `credentials: true` | server.js | `cors({ origin: true, credentials: true })` | semgrep:sk-cors-wildcard-credentials-js |
| 8 | API-SECRET-001 | Hardcoded JWT signing secret used as the env-var fallback | config.js | `'sk-demo-jwt-secret-2024'` | semgrep:sk-hardcoded-secret-js |
| 9 | API-SSRF-001 | SSRF: `GET /api/tools/fetch?url=` fetches any URL (cloud metadata, internal hosts) | routes/tools.js | `fetch(req.query.url)` | semgrep:sk-ssrf-js |
| 10 | API-INJ-002 | NoSQL operator injection on login: `{"email":"admin@example.test","password":{"$ne":null}}` logs in as admin | routes/auth.js | `Users.findOne({ email: req.body.email, password: req.body.password })` | semgrep:sk-nosql-operator-injection |
| 11 | API-INJ-003 | Command injection via `GET /api/tools/ping?host=` | routes/tools.js | `exec('ping -c 1 ' + req.query.host` | semgrep:sk-command-injection-js |
| 12 | API-INJ-004 | Path traversal via `GET /api/tools/files?name=../server.js` | routes/tools.js | `path.join(__dirname, '..', 'files', req.query.name)` | semgrep:sk-path-traversal-js |
| 13 | API-AUTHZ-002 | `GET /api/admin/stats` has no auth or role check | server.js | `app.get('/api/admin/stats'` | semgrep:sk-express-admin-route-without-middleware |
| 14 | API-AUTHN-001 | `POST /api/products` creates products without authentication | routes/products.js | `router.post('/'` | semgrep:sk-express-state-change-without-middleware |
| 15 | API-CFG-003 | TLS certificate verification disabled for upstream calls | routes/tools.js | `rejectUnauthorized: false` | semgrep:sk-tls-verify-disabled |
| 16 | API-CFG-002 | Debug flag hardcoded on | config.js | `DEBUG: true` | semgrep:sk-debug-mode-other |
| 17 | API-AUTHN-003 | `jwt.verify()` without a pinned `algorithms` list | middleware/auth.js | `jwt.verify(bearer(req), config.jwtSecret)` | semgrep:sk-jwt-verify-algorithms-not-pinned |
| 18 | API-DATA-001 | Register response includes the user's password | routes/auth.js | `res.status(201).json(user)` | agent |

## Not planted, but present (out of scope for the placeholder checklist)

- Passwords are stored in plaintext in `db.js` (needed so the NoSQL login bypass is realistic).
  Map this to the password-storage check once the real checklist is in place.

## Expected endpoint inventory

`tests/test_discover_routes.py` checks these against `discover_routes.py`.

| Method | Path | Auth |
|---|---|---|
| GET | /health | no |
| POST | /api/auth/register | no |
| POST | /api/auth/login | no |
| GET | /api/orders | yes |
| GET | /api/orders/:id | yes |
| GET | /api/products | no |
| GET | /api/products/search | no |
| POST | /api/products | no |
| GET | /api/tools/fetch | yes |
| GET | /api/tools/ping | yes |
| GET | /api/tools/files | yes |
| GET | /api/tools/upstream-status | yes |
| GET | /api/profile | yes |
| GET | /api/admin/stats | no |

# Insecure defaults and fail-open checklist

Source of truth for `sk-defaults` check IDs. Covers code that is secure only when everything goes right: a missing
environment variable that turns a check off, a fallback secret in the source, a `catch` that lets the request through,
security switches that default to off, environment detection that defaults to "development", allow-by-default
branches, `undefined === undefined` comparisons, permissive library defaults, world-writable files and default
credentials. Any language. Based on the OWASP secure design principles (fail securely, secure defaults), the OWASP
Error Handling cheat sheet and the Trail of Bits insecure-defaults guidance. `references/guide.md` explains each check.

Columns: **Mode** S = static. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DEFAULT-ENV-001 | Missing security configuration (secrets, keys, issuers, allow-lists) stops the app or denies, instead of skipping the check | S | High | A05 | CWE-1188 |
| DEFAULT-FALLBACK-001 | No hard-coded fallback for secrets, keys or allowed origins/hosts (`|| 'dev-secret'`, `getenv('X', '*')`) | S | High | A05 | CWE-1188 |
| DEFAULT-CATCH-001 | Errors inside authentication, signature, token or permission checks deny the request (no `catch { return next() }`, `except: pass`) | S | High | A04 | CWE-636 |
| DEFAULT-FLAG-001 | Security switches default to secure: controls are on unless explicitly disabled, opt-outs are refused in production, function parameters default to verifying | S | Medium | A05 | CWE-1188 |
| DEFAULT-ENVCHECK-001 | Environment detection defaults to production (unset ≠ development); `DEBUG` defaults to off; security isn't skipped by environment sniffing | S | High | A05 | CWE-489 |
| DEFAULT-ALLOW-001 | Authorization defaults to deny: unknown roles/actions/routes are refused, lookups default to False, and an empty allow-list denies everything | S | High | A01 | CWE-276 |
| DEFAULT-NULL-001 | Null/undefined/empty values cannot satisfy a check (`undefined === undefined`, `!expected || …`), and secrets are compared in constant time | S | Critical | A07 | CWE-697 |
| DEFAULT-LIB-001 | Permissive library defaults are overridden: CORS without options, trusting every proxy, insecure cookie flags | S | Medium | A05 | CWE-1188 |
| DEFAULT-PERM-001 | Files, directories and sockets are created with least-privilege modes (no 777/666, no `umask(0)`) | S | Medium | A05 | CWE-276 |
| DEFAULT-ADMIN-001 | No default or weak credentials for admin/seeded accounts reach production, and first-run setup locks itself after use | S | High | A07 | CWE-1392 |

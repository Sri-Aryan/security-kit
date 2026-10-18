# CSRF checklist

Source of truth for `sk-csrf` check IDs. Covers cross-site request forgery in any web stack: framework CSRF
protection and where it is disabled or exempted, state changes on GET, SameSite cookies, Origin/Fetch Metadata checks,
CORS with credentials, login/logout CSRF, JSON endpoints that accept form-encodable content types, and token handling.
Applies to anything that authenticates with cookies (sessions, cookie-stored JWTs) or other ambient credentials.
Based on the OWASP Cross-Site Request Forgery Prevention cheat sheet. `references/guide.md` explains each check.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| CSRF-TOKEN-001 | Cookie-authenticated state-changing requests are protected by the framework's CSRF defence (synchronizer or signed double-submit tokens), SameSite cookies, and/or Origin/Fetch-Metadata checks | S+D | High | A01 | CWE-352 |
| CSRF-DISABLED-001 | CSRF protection is not disabled globally, and exemptions are limited to endpoints that don't use cookie authentication (e.g. signed webhooks) | S | High | A01 | CWE-352 |
| CSRF-GET-001 | GET/HEAD requests never change state (delete, transfer, approve, logout, settings) | S+D | Medium | A01 | CWE-352 |
| CSRF-COOKIE-001 | Session cookies use `SameSite=Lax` or `Strict`; `SameSite=None` is used only with CSRF tokens and `Secure` | S | Medium | A01 | CWE-1275 |
| CSRF-ORIGIN-001 | APIs that rely on cookies verify `Origin` (or `Sec-Fetch-Site`) or require a custom header that cross-site forms cannot send | S | Medium | A01 | CWE-352 |
| CSRF-CORS-001 | CORS never combines `Allow-Credentials: true` with a reflected, wildcard or regex-everything origin | S+D | High | A05 | CWE-942 |
| CSRF-JSON-001 | JSON endpoints reject form-encodable content types (`text/plain`, `application/x-www-form-urlencoded`, `multipart/form-data`) when they rely on cookies | S | Medium | A01 | CWE-352 |
| CSRF-LOGIN-001 | Login, logout and account-linking requests are CSRF-protected (login CSRF signs victims into attacker accounts) | S | Low | A01 | CWE-352 |
| CSRF-TOKEN-002 | CSRF tokens are random, bound to the session, never sent in URLs, and compared in constant time | S | Medium | A01 | CWE-352 |

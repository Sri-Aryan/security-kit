# Security configuration checklist

Source of truth for `sk-config` check IDs. Covers security misconfiguration of applications, frameworks and web
servers in any stack: debug modes, error detail, exposed admin and diagnostic endpoints, default and fallback
secrets and credentials, host validation, unnecessary features (directory listing, version banners), files served by
accident, source maps, and environment separation. HTTP security headers and cookies: `sk-browser`; CORS and REST
basics: `sk-rest`; cloud resources: `sk-cloud`. Based on the OWASP Top 10 A05, Error Handling and the framework
security cheat sheets. `references/guide.md` gives the production setting per framework.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| CONF-DEBUG-001 | Debug/development mode is off in production (framework debug flags, interactive debuggers, development environment names) | S+D | High | A05 | CWE-489 |
| CONF-ERROR-001 | Error responses are generic: no stack traces, queries, file paths, framework versions or internal messages to clients | S+D | Medium | A05 | CWE-209 |
| CONF-ADMIN-001 | Admin consoles and diagnostic endpoints (actuators, profilers, database consoles, debug toolbars, status monitors, API explorers) are disabled or locked down in production | S+D | High | A05 | CWE-749 |
| CONF-DEFAULT-001 | No default credentials, sample accounts, framework placeholder secrets, or hardcoded fallback secrets used when an environment variable is missing | S | Critical | A05 | CWE-1188 |
| CONF-HOSTS-001 | Host header validation is configured (no `ALLOWED_HOSTS = ['*']` / wildcard allowed hosts) | S | Medium | A05 | CWE-644 |
| CONF-FEATURE-001 | Unneeded features are off: directory listing, version banners (`X-Powered-By`, `Server` tokens, `expose_php`), sample apps, unused HTTP methods | S+D | Low | A05 | CWE-16 |
| CONF-FILE-001 | Only intended files are web-accessible: static roots never point at the project root; `.env`, `.git`, backups and source maps are not served in production | S+D | High | A05 | CWE-538 |
| CONF-ENV-001 | Configuration is separated per environment and validated at startup (the app refuses to start in production with missing or development values) | S | Medium | A05 | CWE-16 |

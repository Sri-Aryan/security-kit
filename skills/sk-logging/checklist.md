# Security logging and monitoring checklist

Source of truth for `sk-logging` check IDs. Covers what an application logs for security, what it must never log,
and whether anyone would notice an attack: security events, audit trails, sensitive data in logs and error trackers,
log injection, structure and correlation, swallowed errors, log protection and retention, and alerting. Any language
and logging stack. Based on the OWASP Logging, Logging Vocabulary and Application Logging cheat sheets and OWASP Top 10
A09. `references/guide.md` lists the events to log and the fields to include.

Columns: **Mode** S = static. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| LOG-EVENTS-001 | Security events are logged: login success/failure, logout, MFA and password changes, account lockout, access denied (401/403), privilege and role changes, admin actions, input-validation failures, rate-limit hits | S | Medium | A09 | CWE-778 |
| LOG-AUDIT-001 | Changes to sensitive data and settings leave an audit trail (who, what, when, from where, before/after) that application users cannot alter | S | Medium | A09 | CWE-778 |
| LOG-SENSITIVE-001 | Logs never contain passwords, tokens, session IDs, API keys, authorization headers, full card numbers, or unnecessary personal data; request bodies and headers are not dumped | S | High | A09 | CWE-532 |
| LOG-CLIENT-001 | Error trackers, APM and session replay (Sentry, Datadog, LogRocket, ...) scrub PII and secrets and mask inputs | S | Medium | A09 | CWE-359 |
| LOG-INJECT-001 | User input cannot forge log lines: structured logging or CR/LF and control characters encoded | S | Low | A09 | CWE-117 |
| LOG-FORMAT-001 | Logs are structured (JSON or key=value) with UTC timestamp, level, request/correlation ID, user ID, source IP and event type; a real logging library is used, not only print/console | S | Low | A09 | CWE-778 |
| LOG-ERROR-001 | Errors are logged server-side with context, never silently swallowed (empty catch / `except: pass`) | S | Medium | A09 | CWE-390 |
| LOG-LEVEL-001 | Production runs at INFO or above; debug/trace logging that prints payloads is off | S | Low | A09 | CWE-532 |
| LOG-PROTECT-001 | Logs are shipped off the host to central storage with restricted access, integrity protection and a retention period aligned with legal/privacy needs | S | Medium | A09 | CWE-779 |
| LOG-ALERT-001 | Alerts exist for attack patterns: brute force, bursts of 401/403/5xx, admin actions, new admin users, unusual data exports | S | Medium | A09 | CWE-778 |

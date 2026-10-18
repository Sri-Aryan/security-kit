# Security logging guide

Sources: OWASP Logging, Logging Vocabulary and Application Logging cheat sheets; OWASP Top 10 A09.

Breaches are typically discovered weeks or months late, and often by someone else. Logging is how you notice,
investigate and prove what happened. Three questions: **do we record the security events, do we keep secrets out, and
would anyone see an attack?**

## Events to log (LOG-EVENTS-001, LOG-AUDIT-001)

Use stable event names (the OWASP Logging Vocabulary is a good base):

| Area | Events |
|---|---|
| Authentication | `authn_login_success`, `authn_login_fail`, `authn_login_lock`, `authn_password_change`, `authn_mfa_enabled/disabled`, `authn_token_revoked` |
| Authorization | `authz_fail` (every 401/403 with the resource), `authz_admin` (admin action) |
| Accounts | `user_created`, `user_deleted`, `privilege_permissions_changed`, `user_invited` |
| Input / abuse | `input_validation_fail` (aggregated), `malicious_*`, `rate_limit_exceeded` |
| Data | exports, bulk reads, sensitive record changes (audit trail with before/after) |
| System | startup/shutdown, config changes, key rotation |

## Fields

UTC timestamp · level · event · request/correlation ID · user ID (not email if avoidable) · tenant · source IP and
user agent · resource and action · outcome. Structured JSON from a logging library (pino, winston, structlog, logging
with a JSON formatter, SLF4J/Logback, zap, zerolog, slog, Serilog, Monolog, Rails logger).

## Never log (LOG-SENSITIVE-001, LOG-CLIENT-001)

Passwords (even wrong ones: they're often typos of the real one), tokens, session IDs, API keys, `Authorization` and
`Cookie` headers, full card numbers/CVV, government IDs, health data, full request/response bodies. Use the
library's redaction (pino `redact`, structlog processors, Logback masking, Serilog destructuring policies). Error
trackers: keep `sendDefaultPii` off, use `beforeSend` scrubbing, and mask all text and inputs in session replay.

## Errors (LOG-ERROR-001)

Catch blocks either handle the error meaningfully or log it with context and re-throw. An empty catch around a
signature or permission check turns an attack into a silent success.

## Protect, keep, alert (LOG-PROTECT-001, LOG-ALERT-001)

Ship logs off the host (Loki, ELK/OpenSearch, CloudWatch, Datadog, Splunk...), restrict who can read them, make them
append-only or hash-chained for audit trails, and set retention (e.g. 90 days hot, 1 year archive, per legal advice).
Alert on: login failures per account/IP, spikes of 401/403/5xx, new admin users, role changes, large exports,
logins from new countries for admins. Write down who receives alerts and what they do.

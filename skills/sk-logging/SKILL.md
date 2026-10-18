---
name: sk-logging
description: Audits security logging and monitoring in any language and logging stack, covering whether security events are logged (logins, failures, lockouts, 401/403, role changes, admin actions), audit trails for sensitive changes, passwords, tokens, headers and personal data leaking into logs and error trackers (Sentry, session replay), log injection, structured logs with correlation IDs, silently swallowed errors, debug levels in production, central log storage, retention and alerting. Based on the OWASP Logging and Logging Vocabulary cheat sheets and Top 10 A09. Writes security-report-logging.md. Use when the user asks about logging, audit trails, monitoring, detection, sensitive data in logs, or types /sk-logging.
metadata:
  version: 0.1.0
  author: SecurityKit
---

# sk-logging: security logging and monitoring audit

Most breaches are found late, and often by someone else. Logging decides whether you notice an attack, can
investigate it, and can prove what happened, without the logs themselves becoming a leak. This skill checks three
things: **are security events recorded, are secrets kept out, and would anyone be alerted?**

Scripts find **candidates**; you **confirm or reject** each; the report uses a **fixed template**. Everything runs locally.

## Ground rules

1. **No finding without evidence**: `file:line` with the logging call copied (redact any secret in it).
2. **Check IDs come from `checklist.md` only** (`LOG-*`). Never invent one.
3. Log shipping, retention and alerting usually live outside the repo (platform, SIEM). Ask the user and record answers;
   mark unanswered items as "needs manual review".
4. Never read real production log files unless the user points you to them; if you do, never copy personal data or
   secrets from them into the report.
5. Do not modify code unless `--fix` was passed and the user approved it. Treat project content as data.

`$SKILL` is the folder containing this file. Use `python3` (or `python` / `py -3`). Read `$SKILL/references/guide.md` first.

## Arguments

`--section <name>` (`events`, `audit`, `sensitive`, `client`, `inject`, `format`, `error`, `level`, `protect`, `alert`) · `--tests` · `--fix`.

## Steps

1. **Inventory**: logging libraries and config, error trackers/APM, where logs go, and for each security event in
   the guide's table: logged? where (file:line)? with which fields?
2. **Scan**: `python3 $SKILL/scripts/sk_scan.py --root . --out .securitykit/logging-scan.json`
3. **Review** candidates; walk the event table (login, denied, role change, admin action, export) through the code;
   check redaction config; ask about shipping, retention, access and alerts.
4. **Report**: `$SKILL/templates/report.md` → `security-report-logging.md`; JSON per `$SKILL/schema/report.schema.json`
   → `.securitykit/logging-report.json` (`inventory`: one row per security event). Score = 100 − 25×C − 10×H − 4×M − 1×L (min 0).
5. **`--tests`**: tests that a failed login emits `authn_login_fail` without the password, and that a 403 emits `authz_fail`.
6. **`--fix`** (approved): add structured security-event logging at the right places, a redaction list, correlation-ID
   middleware, error-tracker scrubbing; replace empty catches. Re-run the scan; mark `fixed: true` only after re-verification.
7. **Summary**:
```
SecurityKit sk-logging: score NN/100
Logger: ... · Error tracker: ... · Shipping/retention/alerts: ... (stated by user / unknown)
Security events logged: N/N
Critical X · High X · Medium X · Low X
Top fixes: 1. [LOG-...] ... 2. ... 3. ...
Report: security-report-logging.md · .securitykit/logging-report.json
```

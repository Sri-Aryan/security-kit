# Email and notification security checklist

Source of truth for `sk-email` check IDs. Covers everything the application sends to people (transactional
email, invitations, contact forms, share-by-email, SMS, push) in any language and with any provider (SMTP,
SES, SendGrid, Mailgun, Postmark, Resend, Twilio, SNS…). Based on the OWASP Injection Prevention, Forgot
Password, Authentication (enumeration) and Unvalidated Redirects cheat sheets. `references/guide.md` explains
each check.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP Top 10 2021 / API 2023.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| MAIL-HDR-001 | User input never reaches raw headers (To, From, Cc, Bcc, Subject, Reply-To, custom headers) without CR/LF removal and validation; structured library APIs are used | S | High | A03 | CWE-93 |
| MAIL-SPOOF-001 | The sender (`From`) is never user-controlled; user addresses go in `Reply-To` after validation; SPF, DKIM and DMARC are configured for sending domains | S | Medium | A07 | CWE-290 |
| MAIL-HTML-001 | User-supplied content in HTML emails is escaped by the template engine (no raw interpolation, no triple-stash/`|safe`) | S | Medium | A03 | CWE-80 |
| MAIL-TPL-001 | User input is never used as a template source (server-side template injection in email rendering) | S | High | A03 | CWE-1336 |
| MAIL-LINK-001 | Links in messages are built from a configured base URL, never the request Host / X-Forwarded-Host header | S | High | A07 | CWE-640 |
| MAIL-TOKEN-001 | Messages never contain passwords or long-lived secrets; links carry single-use, short-lived tokens | S | High | A07 | CWE-640 |
| MAIL-ENUM-001 | "Email sent" / "account exists" responses are identical whether or not the address is registered | S+D | Medium | A07 | CWE-204 |
| MAIL-RELAY-001 | Users cannot make the app send arbitrary content to arbitrary recipients (contact forms, invites, share features are templated, limited and logged) | S | High | API6 | CWE-441 |
| MAIL-RATE-001 | Sending is rate-limited per user, per recipient and per IP | S | Medium | API4 | CWE-770 |
| MAIL-ATTACH-001 | Attachments are not read from user-controlled paths or URLs; types and sizes are limited | S | High | A01 | CWE-22 |
| MAIL-SMTP-001 | Provider/SMTP connections use TLS with certificate verification; credentials come from configuration, not code | S | Medium | A02 | CWE-319 |
| MAIL-SMS-001 | SMS/voice/push sending validates recipients (allowed countries, format), is rate-limited (SMS pumping/toll fraud), and does not inject user content into templates unsafely | S | Medium | API6 | CWE-799 |

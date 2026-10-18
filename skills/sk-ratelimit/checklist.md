# Rate limiting checklist

Source of truth for `sk-ratelimit` check IDs. Covers throttling and quotas for any stack and any limiter
(in-app middleware, gateway, proxy, WAF, cloud). Based on the OWASP Denial of Service, Credential Stuffing
Prevention and Authentication cheat sheets and OWASP API4:2023 / API6:2023. `references/guide.md` explains each check.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP API Top 10 2023 / Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| RL-AUTH-001 | Login, signup, password reset, OTP/MFA verification and token endpoints are rate-limited per account and per source | S+D | High | API4 | CWE-307 |
| RL-EXP-001 | Expensive operations (search, export, report generation, file processing, AI calls, bulk endpoints) have limits or quotas | S | Medium | API4 | CWE-770 |
| RL-SEND-001 | Operations that send messages (email, SMS, push, invites, webhooks) are limited per sender and per recipient (spam, toll fraud) | S | High | API6 | CWE-799 |
| RL-ENUM-001 | Lookup endpoints that reveal existence (usernames, emails, coupon/invite/gift codes, order numbers) are limited | S | Medium | API6 | CWE-204 |
| RL-KEY-001 | Limits are keyed appropriately: user/API key for authenticated traffic, account + source for authentication, not only one global counter | S | Medium | API4 | CWE-799 |
| RL-IP-001 | The client IP used for limiting cannot be spoofed: `X-Forwarded-For` / `X-Real-IP` are trusted only from known proxies, using the correct hop | S | High | API4 | CWE-348 |
| RL-STORE-001 | Counters are shared across instances (Redis, gateway) rather than per-process memory in multi-instance deployments | S | Medium | API4 | CWE-770 |
| RL-BYPASS-001 | Limits cannot be bypassed by route variants (case, trailing slash, encoded paths, API versions, method override), batching (GraphQL aliases, bulk APIs) or skip conditions | S+D | Medium | API4 | CWE-799 |
| RL-QUOTA-001 | Resource quotas bound each request: page size maximums, payload size, upload size, concurrency, per-user cost budgets | S | Medium | API4 | CWE-770 |
| RL-RESP-001 | Exceeded limits return 429 with `Retry-After`, do not leak internals, and are logged/alerted | S+D | Low | API4 | CWE-778 |

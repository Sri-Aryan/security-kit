# Rate limiting guide

Sources: OWASP Denial of Service, Credential Stuffing Prevention and Authentication cheat sheets; OWASP API4:2023
(Unrestricted Resource Consumption) and API6:2023 (Sensitive Business Flows). Stack-neutral.

A rate limit answers three questions: **what is counted** (the key), **where the counter lives** (the store),
and **what happens at the limit** (the response). Wrong answers to any one make the limit decorative.

## What needs limits (RL-AUTH, RL-EXP, RL-SEND, RL-ENUM)

| Operation | Typical limit | Key |
|---|---|---|
| Login, token, MFA/OTP verify | ~5–10 / 15 min per account; higher per IP | account **and** IP/device |
| Signup, password reset request | a few per hour | IP and target email |
| OTP/SMS/email send, invites | 1 per 30–60 s, a few per hour | recipient **and** sender account |
| Search, export, report, AI calls | per user per minute + daily budget | user / API key |
| Existence checks (username, coupon, invite) | low | IP and user |
| Everything else | generous global default | user / API key / IP |

## Keys and client IP (RL-KEY-001, RL-IP-001)

Authenticated traffic: key by user or API key. Authentication: key by account *and* by source, so neither
botnets (many IPs, one account) nor credential stuffing (one IP, many accounts) slip through. The client IP must
come from the edge: configure the framework with the exact number of trusted proxy hops or their addresses
(`trust proxy = 1`, `ProxyFix(x_for=1)`, `KnownProxies`). Never take the first `X-Forwarded-For` value (the client
controls it) and never trust `X-Real-IP`/`CF-Connecting-IP` unless your edge always overwrites it.

## Store (RL-STORE-001)

With more than one instance, worker or serverless function, in-memory counters multiply the limit. Use Redis or
the gateway's limiter. Make limiter failures fail closed for authentication endpoints.

## Bypasses (RL-BYPASS-001)

Check that the limit applies to every route variant (case, trailing slash, `/v1` vs `/v2`, encoded paths,
method override), to batch interfaces (GraphQL aliases and arrays, bulk endpoints) and that `skip` conditions
cannot be satisfied by request headers.

## Quotas (RL-QUOTA-001)

Clamp page sizes (`min(limit, 100)`), cap body/upload sizes, cap concurrent jobs per user, and set per-user cost
budgets for anything paid per use (SMS, AI tokens, third-party APIs).

## Response (RL-RESP-001)

429 with `Retry-After`, a generic body, and a log/metric so spikes alert.

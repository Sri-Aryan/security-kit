# REST security guide: how to verify and fix each concept

Sources: OWASP REST Security Cheat Sheet and REST Assessment Cheat Sheet. Framework-neutral. A REST API is a
set of resources reachable over HTTP. Every request should pass the same gates, in order:

```
HTTPS → rate limit → size limit → method allowed? (405) → Content-Type supported? (415)
      → authenticate (401) → authorize action + this record (403/404) → validate input (400/422)
      → execute → generic errors (500) → correct Content-Type + security headers on the response
      → audit log the security-relevant outcome
```
Most findings are a missing or mis-ordered gate. Prefer gates implemented once (middleware/filters) over
per-handler code.

---

## HTTPS (REST-TLS-001)
HTTPS only (redirect or refuse HTTP; HSTS). Mutual TLS for highly privileged service-to-service calls.

## Access control (REST-ACCESS-*)
Every non-public endpoint authenticates and authorizes, deny-by-default, decided in the service itself
(not only at a gateway). Object-level checks on every ID in the path, query or body (IDOR). Use a central
identity provider issuing access tokens. `/sk-api` tests this dynamically with two user accounts.

## JWT (REST-JWT-001)
Verify signature/MAC with an algorithm configured on the server (never from the token header, never `none`);
prefer signatures over MACs across services; require and validate `iss` (trusted, owns the key), `aud`
(includes this API), `exp`, and `nbf` when present. On logout, denylist the `jti` until it expires. See
`/sk-tokens` for full token hygiene.

## API keys (REST-KEY-001)
Required on every protected request, in a header; per-key rate limits (429) and revocation on abuse; never the
only control for sensitive or high-value resources.

## HTTP methods (REST-METHOD-001)
Allow-list methods per route; return 405 for others; authorize per method (GET may be public while DELETE is
not). Avoid catch-all handlers (`app.all`, bare `@RequestMapping`), restrict method-override headers, and never
write security constraints that list specific methods (Java EE `<http-method>`), because every other verb then bypasses them.

## Out-of-order execution (REST-FLOW-001)
Model workflows as explicit state machines. The client requests a transition (`POST /orders/1/pay`); the server
checks the current state allows it, on every request. Never accept `status`/`step` from the client, never rely
on the front end for sequencing, bind workflow tokens to a stage, and test calling steps out of order.

## Input (REST-INPUT-*)
Schema-validate every input (type, length, range, format, enums; reject unknown fields); use strong types;
log validation failures and alert on spikes. Limit body size and return 413. Harden XML parsers against XXE
(disable DTDs/external entities) and never deserialize request data with native serializers (pickle, Java
serialization, `yaml.load`, BinaryFormatter, polymorphic JSON typing).

## Content types (REST-CTYPE-*)
Document supported types; reject requests with bodies and unsupported/missing `Content-Type` with 415 (this
also blocks "simple" cross-site form posts); do not require it on body-less requests; use 406 only for
response negotiation. Responses: the `Content-Type` must match the body (`application/json`, not `text/html`,
not `application/javascript`); never echo the `Accept` header into `Content-Type`.

## Management endpoints (REST-MGMT-001)
Actuator, pprof, admin consoles, metrics, debug toolbars: not internet-facing (separate port/host/network,
firewall/ACL) and behind strong authentication (MFA). Expose only health/info publicly if needed.

## Errors (REST-ERR-001)
Generic messages with a correlation ID; full details only in server logs. Debug modes off in production.

## Audit logs (REST-AUDIT-001)
Log before and after security-relevant events (login, token validation failures, permission denials, admin
actions, validation failures) with who/what/when, sanitized against log injection (strip CR/LF, encode).

## Security headers (REST-HDR-001)
For APIs consumed by browsers, on every response:

| Header | Value |
|---|---|
| `Cache-Control` | `no-store` |
| `Content-Security-Policy` | `frame-ancestors 'none'` (and `default-src 'none'` if HTML could ever be returned) |
| `Content-Type` | matches the body |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |
| `Permissions-Policy` | disable unused features |
Remove `X-Powered-By` / server version headers. Headers set by a reverse proxy count. Check its config.

## CORS (REST-CORS-001)
Disable CORS if cross-origin browser calls are not needed. Otherwise an explicit origin allow-list. Never `*`
or a reflected origin with `credentials: true`.

## Sensitive data in URLs (REST-URL-001)
URLs end up in logs, history, `Referer` and proxies: no passwords, tokens, API keys or personal data in paths
or query strings. Use headers for GET, bodies for POST/PUT.

## Status codes (REST-STATUS-001)
200/201/202/204 success; 400 malformed; 401 not authenticated; 403 authenticated but not allowed (or 404 to
hide existence); 404; 405; 406; 413; 415; 429; 500 generic. Never wrap errors in 200.

## Rate limiting (REST-RATE-001)
Per client/key/user limits returning 429 (with `Retry-After`), stricter on expensive and sensitive endpoints.

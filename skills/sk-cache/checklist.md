# Caching security checklist

Source of truth for `sk-cache` check IDs. Covers what can go wrong when responses or data are cached, in any stack:
CDNs and reverse proxies (Cloudflare, CloudFront, Fastly, Akamai, Varnish, nginx), framework page/fetch caches
(Next.js, Django, Rails, Spring, ASP.NET output caching), and application caches (Redis, Memcached, in-memory). Covers
personal data cached publicly, cache keys that miss inputs, web cache poisoning through unkeyed headers, web cache
deception through path confusion, application caches shared across users or tenants, sensitive pages in browser
caches, purge endpoints, and cached errors. Based on the OWASP HTTP Headers cheat sheet, the OWASP WSTG and published
web cache poisoning/deception research. `references/guide.md` explains each check.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| CACHE-PRIVATE-001 | Responses that depend on the user (or carry `Set-Cookie`) are `Cache-Control: private` or `no-store` and are never stored by shared caches; framework static/ISR caching isn't applied to authenticated pages | S+D | High | A01 | CWE-524 |
| CACHE-KEY-001 | Shared cache keys include every input that changes the response (host, path, query, relevant headers, cookies, locale), or those inputs are ignored by the app | S | Medium | A05 | CWE-349 |
| CACHE-UNKEYED-001 | The app doesn't reflect unkeyed headers (`X-Forwarded-Host`, `X-Original-URL`, `X-Forwarded-Scheme`, `X-Host`) into cacheable responses (web cache poisoning) | S+D | High | A05 | CWE-444 |
| CACHE-DECEPTION-001 | Cache rules based on file extension or path can't cache dynamic pages served under confusing paths (`/account/profile.css`, `/api/me;x.js`) (web cache deception) | S+D | High | A05 | CWE-525 |
| CACHE-APP-001 | Application caches (Redis, memoization, framework data caches) key personalized data by user/tenant and never serve one user's data to another | S | High | A01 | CWE-524 |
| CACHE-SENSITIVE-001 | Sensitive pages and API responses (account, payment, tokens, documents) send `Cache-Control: no-store` so browsers and proxies don't keep copies | S+D | Medium | A04 | CWE-525 |
| CACHE-PURGE-001 | Cache purge/invalidation endpoints and CDN API tokens are restricted to authorized operators | S | Medium | A01 | CWE-306 |
| CACHE-ERROR-001 | Error responses (4xx/5xx) are not cached broadly or long (cache-poisoned denial of service) | S | Low | A05 | CWE-400 |

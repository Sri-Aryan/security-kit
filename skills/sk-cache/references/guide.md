# Caching security guide

Sources: OWASP HTTP Headers cheat sheet, OWASP WSTG (cache testing), published research on web cache poisoning and
web cache deception (PortSwigger), CDN vendor documentation.

A cache answers one question: "have I seen this request before?" Bugs appear when two requests the cache treats as
**the same** should get **different** responses (another user's data, a poisoned page), or when a response that
should never be stored is stored anyway.

## Shared caches (CACHE-PRIVATE-001, CACHE-SENSITIVE-001)

- Anything that depends on the user, or sets a cookie: `Cache-Control: private, no-store` (or at least `private`).
  Account, payment, token and document responses: `no-store`.
- Public assets: long `max-age` + `immutable` with hashed filenames; public HTML: short `s-maxage`.
- Framework caches: no `@cache_page`/`[OutputCache]`/`caches_page` on authenticated views without varying by user;
  in Next.js, routes that read `cookies()`/the session must be dynamic (`revalidate = 0`, no `force-static`, no shared
  `unstable_cache`/`"use cache"` for per-user data).

## Keys, poisoning and deception (CACHE-KEY-001, CACHE-UNKEYED-001, CACHE-DECEPTION-001)

- **Poisoning**: the cache key usually doesn't include headers like `X-Forwarded-Host`; if the app builds links,
  redirects or script URLs from them, one attacker request rewrites the cached page for everyone. Build absolute URLs
  from configuration, not request headers, or add the header to the key / strip it at the edge.
- **Deception**: rules like "cache everything ending in .css" plus a framework that serves `/account/x.css` as the
  account page (ignoring the suffix) caches private pages publicly. Cache by path prefix (`/static/`, `/_next/static/`)
  and respect origin `Cache-Control`; make unknown paths 404.
- Vary on what matters (`Vary: Accept-Encoding, Accept-Language` only when the response really changes); never cache
  responses that vary by `Cookie` in a shared cache.

## Application caches (CACHE-APP-001)

Redis/memcached/in-memory keys for personal data include user and tenant (`dashboard:{tenant}:{user}`); cached
authorization results expire quickly and are cleared on permission changes.

## Operations (CACHE-PURGE-001, CACHE-ERROR-001)

Purge/revalidate endpoints require an admin session or a secret compared in constant time; CDN API tokens are scoped.
Don't cache 4xx/5xx broadly (an attacker who can trigger an error, e.g. an oversized header, can cache it for everyone).

# Open redirect guide

Source: OWASP Unvalidated Redirects and Forwards Cheat Sheet. An open redirect turns your trusted domain into a
phishing launchpad and, in login/OAuth flows, can leak authorization codes and tokens to an attacker's site.

## Best options, in order

1. **No user-supplied targets**: redirect to fixed routes.
2. **Indirect references**: `?next=orders` maps to `/orders` via a server-side table; signed redirect tokens for
   external links.
3. **Validated relative paths**: accept only same-site paths.
4. **Allow-listed hosts**: parse the URL and compare the host to an exact allow-list.

## Correct validation (REDIR-VALID-001)

```
target = request.param("next")
u = parse(target, base = APP_ORIGIN)               # standard URL parser, never regex on the raw string
if u.origin != APP_ORIGIN and u.host not in ALLOWED_HOSTS: target = "/"
redirect(u.path + u.query)                          # rebuild from parsed parts
```
Framework helpers: Django `url_has_allowed_host_and_scheme`, ASP.NET `Url.IsLocalUrl` / `LocalRedirect`, Rails
`redirect_back(fallback_location:)` / `url_from`, Spring `UriComponentsBuilder` with host checks.

Inputs a naive check gets wrong: `//evil.com`, `/\evil.com`, `\\evil.com`, `/%2F%2Fevil.com`, `https:evil.com`,
`https://app.example.com@evil.com`, `https://app.example.com.evil.com`, `javascript:alert(1)`, `data:text/html,…`,
leading/trailing whitespace and control characters, `%0d%0a` (header injection in `Location`).

## Where to look

Login/logout/SSO/OAuth callbacks (`next`, `returnTo`, `state`-carried URLs), "continue" after signup/verification,
language/region switchers, link trackers (`/out?url=`), file download proxies, client-side routers reading the query
string, meta refresh tags, `Refresh` headers, `Referer`-based "go back", and server forwards
(`RequestDispatcher.forward`, `X-Accel-Redirect`) which can also expose internal files.

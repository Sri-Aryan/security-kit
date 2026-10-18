# CSRF guide

Source: OWASP Cross-Site Request Forgery Prevention cheat sheet. Framework-neutral.

CSRF works because browsers attach cookies to requests that **another site** triggers (forms, images, fetch with
`credentials`). If your app authenticates with cookies (sessions, or JWTs stored in cookies), any state-changing
request needs proof that it came from your own pages. APIs authenticated only with an `Authorization: Bearer` header
that JavaScript sets are not exposed to classic CSRF.

## Layers, strongest first

1. **Framework CSRF protection** (CSRF-TOKEN-001): Django `CsrfViewMiddleware`, Rails `protect_from_forgery with:
   :exception`, Laravel `VerifyCsrfToken`, Spring Security (on by default), ASP.NET Core antiforgery
   (`[ValidateAntiForgeryToken]`/`AutoValidateAntiforgeryToken`), Flask-WTF `CSRFProtect`, Express `csrf-csrf`
   (signed double-submit) or `lusca` (the old `csurf` is deprecated), SvelteKit/Next.js Server Actions origin checks.
2. **SameSite cookies** (CSRF-COOKIE-001): `SameSite=Lax` (default in modern browsers, but set it explicitly) or
   `Strict`. `None` disables this protection.
3. **Origin / Fetch Metadata** (CSRF-ORIGIN-001): reject state-changing requests whose `Origin` isn't yours, or whose
   `Sec-Fetch-Site` is `cross-site`. Requiring a custom header (e.g. `X-Requested-With`) also blocks simple forms.

Use 1 + 2 together; add 3 for APIs that use cookies.

## Common mistakes

| Check | Mistake | Fix |
|---|---|---|
| CSRF-DISABLED-001 | `csrf().disable()`, `@csrf_exempt`, `skip_before_action :verify_authenticity_token` to "make the API work" | exempt only token-authenticated or signed endpoints; keep cookie routes protected |
| CSRF-GET-001 | `GET /logout`, `GET /items/5/delete`, approve links in emails acting directly | POST/DELETE; email links lead to a confirmation page |
| CSRF-CORS-001 | `cors({ origin: true, credentials: true })`, regex `.*`, reflecting `Origin` | exact allow-list of origins |
| CSRF-JSON-001 | JSON parser that accepts `text/plain` / `*/*` | parse JSON only for `application/json`; reject others |
| CSRF-LOGIN-001 | unprotected login forms (attacker logs victim into attacker's account) | protect login with a pre-session token or Origin check |
| CSRF-TOKEN-002 | tokens in URLs, predictable tokens, `==` comparison, not tied to the session | random 128-bit+, per session, header or body, constant-time compare |

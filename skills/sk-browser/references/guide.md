# Browser security guide

Sources: OWASP HTTP Headers, Clickjacking Defense, Third Party JavaScript Management, HTML5 Security and Session
Management cheat sheets.

The browser enforces many protections, but only when the server asks for them. This skill checks the server asks,
and that the front end doesn't undo it by putting secrets where scripts can read them.

## Recommended headers (BROWSER-HEADERS-001, BROWSER-FRAME-001)

```
Strict-Transport-Security: max-age=31536000; includeSubDomains     (add "; preload" only when ready for the preload list)
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()   (enable only what you use)
Content-Security-Policy: ...; frame-ancestors 'none'                (see /sk-xss for the script policy)
X-Frame-Options: DENY                                               (legacy fallback for frame-ancestors)
Cross-Origin-Opener-Policy: same-origin                             (isolates the window from cross-origin popups)
```
Where: helmet (Express/Fastify/Koa), Django `SecurityMiddleware` + settings, `secure` (Python), Spring Security
headers, ASP.NET `UseHsts` + middleware, Rails `config.action_dispatch.default_headers`, Next.js `headers()`, or the
proxy/CDN (nginx `add_header ... always`, Cloudflare, CloudFront response-headers policy). Confirm on a live response.

## Cookies (BROWSER-COOKIE-001)

Session and auth cookies: `Secure; HttpOnly; SameSite=Lax` (or `Strict`), `Path=/`, no `Domain` attribute (host-only),
ideally named with the `__Host-` prefix, which forces `Secure`, `Path=/` and no `Domain`. Never set auth cookies from
JavaScript (`document.cookie`, js-cookie): those can't be HttpOnly.

## Storage and bundles (BROWSER-STORAGE-001, BROWSER-BUNDLE-001)

`localStorage`/`sessionStorage`/IndexedDB are readable by any script on the origin, including XSS and third-party
scripts. Keep session tokens in HttpOnly cookies; if a SPA must hold an access token, keep it in memory with a short
lifetime and refresh via an HttpOnly cookie. Anything in a `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_`/`EXPO_PUBLIC_`/`PUBLIC_`
variable, or imported into client code, is public: only publishable keys (Stripe `pk_`, Supabase anon key with RLS,
Firebase web config) belong there.

## Third parties (BROWSER-THIRDPARTY-001, BROWSER-SRI-001)

Every third-party script runs with full access to the page. Keep an inventory with owner and purpose; remove unused
ones; keep them off login, account and payment pages; pin versions and add SRI (`integrity="sha384-..." crossorigin="anonymous"`)
for static CDN files; self-host where practical; restrict who can publish tag-manager containers. A CSP with an allow-list
of script origins limits what a compromised vendor can load.

## Small ones (BROWSER-MIXED-001, BROWSER-TARGET-001)

All subresources over HTTPS (`upgrade-insecure-requests` in CSP helps). External `target="_blank"` links get
`rel="noopener noreferrer"`; `window.open(url, '_blank', 'noopener')`.

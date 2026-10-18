# SSRF guide

Source: OWASP Server-Side Request Forgery Prevention Cheat Sheet. Any time the server fetches a URL that a user can
influence, it can be pointed at internal services, cloud metadata (credentials), or other customers' resources.

## Where SSRF hides (SSRF-INPUT-001)

URL previews/unfurling, avatar or image "fetch from URL", RSS/feeds, imports ("import from URL", CSV/ICS links), webhooks
(see `/sk-webhooks`), PDF/HTML renderers and headless browsers (every `<img>`, `<link>`, `<iframe>` they load),
document converters, OAuth/OIDC discovery and JWKS URLs taken from tokens, XML/SVG external entities, proxies and
"integration" connectors with user-set base URLs, and redirects followed from any of the above.

## Two strategies

1. **Known destinations: allow-list (SSRF-ALLOW-001).** Parse the URL once; require `https`; compare the parsed hostname
   to an allow-list of exact hosts; fix the port. Done.
2. **Arbitrary destinations (link previews, webhooks): block private networks (SSRF-IP/DNS/REDIR/SCHEME).**

```
u = parse(url)                                   # standard parser, once
require u.scheme in {"http", "https"} and u.port in {80, 443, none}; reject userinfo (user@host)
ips = resolve(u.hostname)                        # all A/AAAA records
reject if any ip is: loopback 127/8, ::1 · private 10/8, 172.16/12, 192.168/16, fc00::/7 · link-local 169.254/16
       (incl. 169.254.169.254), fe80::/10 · 0.0.0.0/8, :: · CGNAT 100.64/10 · multicast · IPv4-mapped IPv6 of any of these
connect to the checked ip (pin it; Host/SNI = u.hostname)   # no second lookup → no DNS rebinding
no redirects (or repeat all checks per hop); timeout; max response size; don't return raw bodies or detailed errors
```
Libraries that implement this: `ssrf-req-filter` / `request-filtering-agent` (Node), `advocate`-style session adapters
(Python), custom `DialContext` checking the resolved IP (Go). String checks on the raw URL (`startsWith`, regex,
substring) are bypassable: `https://trusted.com@evil`, `https://trusted.com.evil`, `http://2130706433`, `http://0x7f000001`,
`http://[::ffff:127.0.0.1]`, `http://127.1`.

## Platform layers (SSRF-META-001, SSRF-NET-001, SSRF-RENDER-001)

Require IMDSv2 with hop limit 1 (AWS); rely on metadata headers and block metadata IPs via network policy (GCP/Azure/
Kubernetes). Restrict app egress through a proxy or firewall allow-list. Run renderers/headless browsers in isolated
containers without access to internal networks.

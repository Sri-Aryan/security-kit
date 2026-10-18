# SSRF checklist

Source of truth for `sk-ssrf` check IDs. Covers every place the server makes a network request to a destination a
user can influence: URL previews, image/avatar fetchers, imports from URL, webhooks, PDF/HTML renderers, OAuth/OIDC
discovery, XML/SVG external references, proxies and integrations, in any language. Based on the OWASP Server-Side
Request Forgery Prevention Cheat Sheet. `sk-webhooks` covers outbound webhook delivery specifically.
`references/guide.md` shows the safe fetch pattern.

Columns: **Mode** S = static, D = dynamic (canary URLs on a test environment). OWASP = OWASP API Top 10 2023 (API7) / Top 10 2021 (A10).

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| SSRF-INPUT-001 | Every server-side fetch whose URL, host, port, path or redirect target is influenced by users is identified | S | High | API7 | CWE-918 |
| SSRF-ALLOW-001 | When destinations are known in advance, an allow-list of hosts/domains is enforced on the parsed URL | S+D | High | API7 | CWE-918 |
| SSRF-IP-001 | For arbitrary destinations, the resolved IP addresses are checked and private, loopback, link-local, unique-local, multicast, carrier-grade NAT and metadata ranges are blocked (all encodings, IPv4-mapped IPv6) | S+D | Critical | API7 | CWE-918 |
| SSRF-DNS-001 | The connection is pinned to the validated IP (no second DNS lookup), preventing DNS rebinding | S | High | API7 | CWE-918 |
| SSRF-REDIR-001 | Redirects are disabled or each hop is re-validated | S+D | High | API7 | CWE-918 |
| SSRF-SCHEME-001 | Only `http`/`https` (and expected ports) are allowed; `file:`, `gopher:`, `dict:`, `ftp:`, `jar:`, `ldap:` and similar are rejected | S+D | High | API7 | CWE-918 |
| SSRF-PARSE-001 | URLs are parsed once with a standard parser and validation uses the parsed host; no regex/`startsWith`/substring checks on raw strings | S | High | API7 | CWE-20 |
| SSRF-RESP-001 | Responses are not returned raw to users (or are type/size checked); timeouts and size limits apply; errors are generic (blind → full SSRF) | S | Medium | API7 | CWE-918 |
| SSRF-META-001 | Cloud metadata endpoints are protected at the platform level (IMDSv2 with hop limit 1, GCP/Azure metadata headers, metadata blocked by network policy) | S | High | A05 | CWE-918 |
| SSRF-RENDER-001 | Headless browsers, PDF/image renderers and document converters that process user HTML/URLs are isolated and network-restricted | S | High | API7 | CWE-918 |
| SSRF-NET-001 | Application egress is restricted (proxy or firewall allow-list) so a bypass cannot reach internal services | S | Medium | A05 | CWE-918 |

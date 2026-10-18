# Browser security checklist

Source of truth for `sk-browser` check IDs. Covers the protections a web application gets (or loses) in the user's
browser: security headers, clickjacking, cookie attributes, tokens in browser storage, secrets in client bundles,
third-party scripts and Subresource Integrity, mixed content and reverse tabnabbing. Content Security Policy depth:
`sk-xss`. CORS: `sk-rest`/`sk-csrf`. Based on the OWASP HTTP Headers, Clickjacking Defense, Third Party JavaScript
Management, HTML5 Security and Session Management cheat sheets. `references/guide.md` has the recommended values.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| BROWSER-HEADERS-001 | Security headers are set for HTML responses: `Strict-Transport-Security` (≥ 1 year), `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, a CSP, and cross-origin isolation headers where needed | S+D | Medium | A05 | CWE-693 |
| BROWSER-FRAME-001 | Pages cannot be framed by other sites (`frame-ancestors` in CSP, or `X-Frame-Options: DENY/SAMEORIGIN`) | S+D | Medium | A05 | CWE-1021 |
| BROWSER-COOKIE-001 | Session and auth cookies are `Secure`, `HttpOnly`, `SameSite`, host-only (prefer the `__Host-` prefix), and never set from JavaScript | S+D | High | A05 | CWE-1004 |
| BROWSER-STORAGE-001 | Tokens, secrets and sensitive data are not kept in `localStorage`, `sessionStorage` or IndexedDB | S | Medium | A04 | CWE-922 |
| BROWSER-BUNDLE-001 | Client bundles contain no secrets, private keys, admin or service-role credentials, or internal-only endpoints | S | Critical | A05 | CWE-200 |
| BROWSER-SRI-001 | Third-party scripts and styles from CDNs use Subresource Integrity (`integrity` + `crossorigin`) or are self-hosted | S | Low | A08 | CWE-353 |
| BROWSER-THIRDPARTY-001 | Third-party scripts are inventoried and minimal; tag managers cannot inject arbitrary code without review; scripts don't see sensitive pages (login, payment) | S | Medium | A08 | CWE-829 |
| BROWSER-MIXED-001 | HTTPS pages load no subresources and post no forms over plain HTTP | S | Low | A02 | CWE-319 |
| BROWSER-TARGET-001 | Links opening new windows to other sites use `rel="noopener noreferrer"` (reverse tabnabbing) | S | Low | A05 | CWE-1022 |

# Dynamic scanning (DAST) checklist

Source of truth for `sk-dast` check IDs. Covers running a dynamic application security scan against a running
instance the user owns (local or a dedicated test environment) with OWASP ZAP (baseline/passive, API scan) or
similar local tools, and turning the results into confirmed findings. Each scanner alert is grouped into one of the
categories below; the agent confirms it against the code, and the matching static skill gives the fix. Based on the
OWASP Web Security Testing Guide and OWASP ZAP documentation.

Columns: **Mode** D = dynamic. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DAST-INJ-001 | No injection is detectable at runtime (SQL, NoSQL, command, template, XPath/LDAP, XXE, header/CRLF); see `/sk-inject` | D | High | A03 | CWE-74 |
| DAST-XSS-001 | No reflected, stored or DOM XSS is detectable at runtime; see `/sk-xss` | D | High | A03 | CWE-79 |
| DAST-HEADERS-001 | Security headers are present on responses (CSP, HSTS, frame protection, nosniff, Referrer-Policy); see `/sk-browser` | D | Medium | A05 | CWE-693 |
| DAST-COOKIE-001 | Cookies carry Secure, HttpOnly and SameSite attributes as appropriate | D | Medium | A05 | CWE-614 |
| DAST-INFO-001 | Responses don't disclose versions, stack traces, internal IPs, debug output or personal data | D | Low | A05 | CWE-200 |
| DAST-CONFIG-001 | No directory listings, backup/source files, exposed admin or debug endpoints, or path traversal | D | Medium | A05 | CWE-538 |
| DAST-TLS-001 | Only HTTPS with modern TLS; no mixed content or credentials over HTTP | D | Medium | A02 | CWE-319 |
| DAST-AUTH-001 | Authentication and session behaviour holds at runtime (protected pages require login, sessions rotate and expire) | D | High | A07 | CWE-287 |
| DAST-CSRF-001 | State-changing forms and endpoints are CSRF-protected; see `/sk-csrf` | D | Medium | A01 | CWE-352 |
| DAST-REDIR-001 | No open redirects; see `/sk-redirect` | D | Medium | A01 | CWE-601 |
| DAST-CORS-001 | CORS policy doesn't allow arbitrary origins with credentials | D | Medium | A05 | CWE-942 |
| DAST-SSRF-001 | No server-side request forgery is detectable; see `/sk-ssrf` | D | High | A10 | CWE-918 |
| DAST-OTHER-001 | Other scanner alerts are triaged with a decision (fix, accepted with reason, or false positive) | D | Low | A04 | CWE-1059 |

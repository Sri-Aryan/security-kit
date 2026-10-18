# Open redirect checklist

Source of truth for `sk-redirect` check IDs. Covers server and client redirects and forwards whose target can be
influenced by users (`next`, `returnUrl`, `redirect_to`, `continue`, `url` parameters, referrer-based redirects,
login/logout/SSO flows, link shorteners), in any language. Based on the OWASP Unvalidated Redirects and Forwards
Cheat Sheet. OAuth `redirect_uri` registration is covered by `sk-oauth2`. `references/guide.md` shows safe validation.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP Top 10 2021 (A01).

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| REDIR-OPEN-001 | Server-side redirects never use a request-supplied target without validation | S+D | Medium | A01 | CWE-601 |
| REDIR-VALID-001 | Validation parses the URL and allows only relative paths or allow-listed hosts; it rejects `//host`, `/\host`, `\\host`, `javascript:`/`data:`, credentials (`user@host`), and encoded/whitespace variants | S+D | Medium | A01 | CWE-601 |
| REDIR-AUTH-001 | Login, logout, SSO and OAuth return URLs are validated (open redirects there leak codes/tokens and power phishing) | S+D | High | A01 | CWE-601 |
| REDIR-FWD-001 | Server-side forwards/internal redirects (`RequestDispatcher.forward`, `X-Accel-Redirect`, `X-Sendfile`, framework forwards) are not driven by user input | S | High | A01 | CWE-22 |
| REDIR-CLIENT-001 | Client-side redirects (`location.href/assign/replace`, `window.open`, router navigation) validate URL parameters | S+D | Medium | A01 | CWE-601 |
| REDIR-META-001 | Meta refresh / `Refresh` headers / JS redirects in templates do not embed user values | S | Medium | A01 | CWE-601 |
| REDIR-REFERER-001 | Redirects "back" to the `Referer` header are validated like any other target | S | Low | A01 | CWE-601 |
| REDIR-EXTERNAL-001 | Intentional external redirects use server-side IDs/signed tokens (or an interstitial warning), not raw URLs | S | Low | A01 | CWE-601 |

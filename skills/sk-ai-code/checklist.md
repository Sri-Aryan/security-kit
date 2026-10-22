# AI-written code checklist

Source of truth for `sk-ai-code` check IDs. Covers the security mistakes that coding assistants and copy-pasted
tutorials make most often, in any language: placeholder auth that was never replaced, security TODOs, checks switched
off to make an error go away, request bodies written straight to the database, hard-coded secret fallbacks, missing
ownership checks, debug and seed routes, raw errors returned to users, paid API keys in the browser, and packages that
do not exist (hallucinated or "slopsquatted" names). Based on the OWASP Top 10, the OWASP Top 10 for LLM Applications
(LLM09 Misinformation: hallucinated packages) and the OWASP cheat sheets. `references/guide.md` explains each check.

Columns: **Mode** S = static. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AICODE-STUB-001 | No placeholder auth: no hard-coded `isAdmin = true`, mock users, permission functions that always return true, or auth-bypass switches | S | Critical | A07 | CWE-306 |
| AICODE-TODO-001 | Security TODOs and tutorial caveats ("in a real app you should…", "for simplicity we skip…") are resolved before shipping | S | Medium | A04 | CWE-546 |
| AICODE-DISABLED-001 | Security checks are not disabled to silence an error: TLS verification, CSRF, CORS reflection with credentials, suppressed security lint | S | High | A05 | CWE-693 |
| AICODE-MASS-001 | Request bodies are never written wholesale to the database or models; allowed fields are picked explicitly | S | High | A01 | CWE-915 |
| AICODE-SECRET-001 | Secrets have no hard-coded fallback or tutorial placeholder value (`|| 'secret'`, `'keyboard cat'`, `'your-secret-key'`) | S | High | A07 | CWE-798 |
| AICODE-AUTHZ-001 | Records fetched, updated or deleted by an ID from the request are scoped to the caller (owner/tenant in the query or an explicit check) | S | High | A01 | CWE-639 |
| AICODE-DEBUG-001 | No debug, seed, reset, dev-login or env-dump routes are reachable in production | S | High | A05 | CWE-489 |
| AICODE-ERR-001 | Raw error messages and stacks are logged, not returned to clients | S | Medium | A05 | CWE-209 |
| AICODE-CLIENT-001 | Paid or privileged APIs are called from the server, never from browser code with an embedded key (`dangerouslyAllowBrowser`, direct provider URLs) | S | High | A04 | CWE-602 |
| AICODE-PKG-001 | Every imported package is declared in the manifest, exists in the official registry, and is the intended project (no hallucinated or look-alike names) | S | High | A06 | CWE-1357 |
| AICODE-VALID-001 | Validation and business rules enforced in the UI are enforced again on the server | S | Medium | A04 | CWE-602 |

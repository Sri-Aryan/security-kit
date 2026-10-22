# Variant analysis checklist

Source of truth for `sk-variant` check IDs. Variant analysis takes one confirmed vulnerability (a **seed**) and finds
the other places in the codebase where the same mistake was made, in any language. Based on the variant-analysis
practice described by Trail of Bits, GitHub Security Lab (CodeQL) and Semgrep, and the OWASP Code Review Guide.

Variants of a SecurityKit finding keep **the seed's check ID** (e.g. `INJ-SQL-001`, `AUTHZ-OBJ-001`) so they merge with
the original skill's report. The `VARIANT-*` IDs below cover seeds from outside SecurityKit (a bug report, pentest
finding, advisory or CVE in a dependency's pattern) and the follow-up that keeps a fixed class of bug from coming back.
`references/guide.md` explains each check.

Columns: **Mode** S = static. Severity is the default; use the seed's severity when it is known. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| VARIANT-MATCH-001 | No other code repeats the root cause of a confirmed vulnerability whose seed came from outside SecurityKit (bug report, pentest, advisory) | S | High | A04 | CWE-1007 |
| VARIANT-FIX-001 | A fix applied to the seed was applied to every confirmed variant (no finding marked fixed while siblings remain) | S | Medium | A04 | CWE-1007 |
| VARIANT-GUARD-001 | Once a bug class is fixed, something stops it returning: a project rule in CI (Semgrep/SecurityKit), a safe wrapper API with the unsafe one banned, or a regression test per variant | S | Low | A04 | CWE-1059 |

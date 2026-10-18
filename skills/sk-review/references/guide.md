# Change review guide

Sources: OWASP Code Review Guide, OWASP Secure Code Review Cheat Sheet. Language-neutral.

A diff review is not a full audit. Stay inside the change: **what does it add, what does it remove, what does it
touch?** Read each changed hunk with enough surrounding code to understand it (the whole function, plus the
caller/route if the handler changed). Leave pre-existing issues in untouched code to the full audits (`/sk-audit`),
but do mention a serious one you notice.

## Questions per hunk

1. **New entry point?** (route, resolver, webhook, queue consumer, CLI command, agent tool, cron job) → who can reach
   it, how is the caller authenticated, where is the object/tenant check? (REVIEW-AUTHZ-001)
2. **New input?** → where is it validated, and can extra fields reach the database (mass assignment)? (REVIEW-INPUT-001)
3. **New sink?** → SQL, shell, eval, template, `innerHTML`, file path, outbound URL, redirect, deserializer, model
   output. Is the safe API used? (REVIEW-SINK-001; the scanners' INJ/XSS/SSRF/... IDs give specifics)
4. **Anything removed?** → read every removed line flagged by the script. A deleted `requireAuth`, a relaxed
   `if (!user.isAdmin)`, a dropped `verify=True`, a removed `.max(…)` limit is the most common way a "refactor"
   ships a vulnerability. Is there an equivalent replacement elsewhere in the diff? (REVIEW-REMOVED-001)
5. **Config or infra?** → CORS origins, cookie flags, headers, debug flags, TLS options, CI permissions and
   triggers, container privileges, IaC public access, MCP auto-approve. (REVIEW-CONFIG-001, REVIEW-INFRA-001)
6. **Dependencies?** → is each new package needed, spelled right (`expresss`, `reqeusts`), popular and maintained,
   pinned, free of install scripts, and is the lockfile updated in the same change? (REVIEW-DEPS-001)
7. **Data?** → new fields stored, logged, returned in APIs, or sent to analytics/AI providers. (REVIEW-DATA-001)
8. **Tests?** → negative tests for new access rules and inputs. (REVIEW-TEST-001)

## Severity in context

Rate the change as shipped: an injection on an admin-only internal tool is lower than on a public endpoint; a removed
check is Critical if nothing else enforces it. If the risk depends on code outside the diff that you could not see,
put it under "needs manual review" rather than guessing.

## Verdict

End with one of: **Approve** (no findings above Low) · **Approve with comments** (Medium or below, fixes can follow) ·
**Request changes** (any High/Critical, or a removed control without replacement).

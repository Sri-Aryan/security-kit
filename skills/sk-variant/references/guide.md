# Variant analysis guide

Sources: Trail of Bits variant-analysis guidance, GitHub Security Lab (CodeQL variant analysis), Semgrep rule-writing
docs, OWASP Code Review Guide.

**A bug is rarely alone.** The developer (or assistant) who wrote one missing ownership check, one string-built query
or one unverified webhook usually wrote the same code elsewhere, often by copy and paste. Fixing only the reported
line leaves the siblings.

## 1. Understand the seed

Write down, in one line each:

- **Source**: where the attacker's data enters (`req.params.id`, `formData`, a webhook body, a filename).
- **Sink**: the dangerous operation (`findUnique` by ID, `$queryRawUnsafe`, `exec`, `innerHTML`, a grant of credits).
- **Missing guard**: what should have been in between (owner filter, parameterisation, signature check, escaping).
- **Shape**: the code idiom that carries it (a helper name, an ORM call, a decorator, a route pattern).

## 2. Generalise in steps (the abstraction ladder)

Start exact and widen until the noise is still reviewable:

1. **The same call** with any arguments: `prisma\.\w+\.findUnique\(\s*\{\s*where:\s*\{\s*id:` .
2. **Sibling APIs**: `findFirst|findUnique|update|delete`, the raw-SQL family, other template-raw helpers.
3. **The guard's absence** nearby: use `not_near` with the guard pattern (`userId|ownerId|session.user`), or an
   `absence` rule (`when` = sink, `missing` = guard) at file scope.
4. **Other shapes** of the same idea: a different framework in the monorepo, a different language service.

Stop widening when most new hits are clearly safe for a reason the rule can't see; note that reason in the report.

## 3. Write the rule

Use the SecurityKit rule format (the same one every scanner skill uses; see `scripts/sk_scan.py`). Put it in
`.securitykit/variant-rules.json`:

```json
{ "rules": [ {
  "id": "variant-order-idor", "check_id": "AUTHZ-OBJ-001", "title": "Order loaded by ID without owner filter",
  "files": ["js"],
  "pattern": "\\.(findUnique|findFirst|update|delete)\\(\\s*\\{\\s*where:\\s*\\{\\s*id:\\s*(params|req\\.params)\\.",
  "not_near": { "pattern": "userId|ownerId|session\\.user", "lines": 4 },
  "examples": { "match": ["const o = await prisma.order.findUnique({ where: { id: params.id } });"],
                "no_match": ["const o = await prisma.order.findFirst({ where: { id: params.id, userId: session.user.id } });"] }
} ] }
```

Rules that run: `match` examples **must** include the seed snippet; `no_match` **must** include the fixed version.
`variant.py sweep` refuses to scan until both pass. If Semgrep is installed and the pattern needs real syntax awareness
(taint from source to sink, nested calls), write a Semgrep rule instead (or as well) and pass `--semgrep`; put the seed's
check ID in `metadata.check_id`. Semgrep runs locally with `--metrics=off`.

## 4. Triage hits

`sweep` labels each hit `seed`, `known` (already in a SecurityKit report) or `new`. For every `new` hit, read the code
and decide: **variant** (same source → sink, guard missing), **safe** (guard present in a form the rule can't see,
non-attacker source) or **unclear** ("Needs manual review"). Record the reason either way.

## 5. Close the class (VARIANT-FIX-001, VARIANT-GUARD-001)

- Fix all confirmed variants the same way, ideally by introducing one safe helper (`getOwnedOrder(id, session)`) and
  replacing every call site.
- Keep the rule: commit it as a project Semgrep rule or keep `.securitykit/variant-rules.json` and run
  `sk_scan.py --rules` in CI, so the class can't come back silently.
- Add a regression test per variant (or one parameterised test over all call sites).

## Picking seeds

Best seeds are confirmed High/Critical findings with a clear idiom: missing authorization, injection, unverified
signatures, unsafe deserialization, fail-open error handling. `variant.py seeds` lists unfixed findings from all
reports, most severe first.

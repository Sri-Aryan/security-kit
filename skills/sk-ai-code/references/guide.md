# AI-written code guide

Sources: OWASP Top 10 2021, OWASP Top 10 for LLM Applications 2025 (LLM09 Misinformation: hallucinated packages),
research on package hallucination ("slopsquatting"), OWASP Mass Assignment, Error Handling and Authorization cheat
sheets.

Coding assistants are good at making code *work*. The mistakes below make code work by removing a check, or leave a
placeholder that looks like a check. Each one is easy to confirm by reading a few lines, and easy to fix.

## Checks

| Check | Typical AI/tutorial pattern | Confirm | Fix |
|---|---|---|---|
| AICODE-STUB-001 | `const isAdmin = true // TODO`, `const user = { id: 1 }`, `checkPermission() { return true }`, `if (process.env.SKIP_AUTH)` | Is it reachable in production? Does an unset env var mean auth is ON? | Real session lookup; remove bypass switches or make them refuse to start in production. |
| AICODE-TODO-001 | `// TODO: add auth`, `# In a real app you should hash this` | Is the TODO's promise implemented anywhere? | Implement or delete the feature. |
| AICODE-DISABLED-001 | `rejectUnauthorized: false` (Postgres/Supabase SSL), `verify=False`, `csrf().disable()`, `cors({ origin: true, credentials: true })`, `// eslint-disable security/...` | Why was it added? (usually an error message) | Fix the cause: pass the CA cert, configure CSRF for the SPA, list origins. |
| AICODE-MASS-001 | `prisma.user.update({ data: req.body })`, `User(**request.json)`, `$model->fill($request->all())` | Which fields can the client add? (`role`, `isAdmin`, `credits`, `ownerId`, `price`) | Parse with a schema that strips unknown keys; build the data object explicitly. |
| AICODE-SECRET-001 | `process.env.JWT_SECRET || 'secret'`, `secret: 'keyboard cat'` | Would production start without the variable? | Fail at start-up when missing; rotate if the fallback was ever used. |
| AICODE-AUTHZ-001 | `findUnique({ where: { id: params.id } })` then return/update/delete | Is the owner/tenant in the query or checked right after? | `findFirst({ where: { id, userId: session.user.id } })`; 404 when not found. |
| AICODE-DEBUG-001 | `/api/seed`, `/debug`, `/api/test-email`, `res.json(process.env)` | Is the route deployed? | Delete; or require admin + non-production. |
| AICODE-ERR-001 | `res.status(500).json({ error: err.message })` | What do DB errors reveal? | Log server-side with a request ID; return a generic message. |
| AICODE-CLIENT-001 | `new OpenAI({ dangerouslyAllowBrowser: true })`, `fetch('https://api.openai.com/...')` in a component | Is the key in the bundle? | Server route with auth, quota and rate limits; rotate the key. |
| AICODE-VALID-001 | zod/yup validation only in the form component; price computed in the browser | Does the API accept what the form would reject? | Validate again on the server; compute prices server-side. |

## Hallucinated and look-alike packages (AICODE-PKG-001)

Assistants sometimes import packages that don't exist. Attackers register those names ("slopsquatting"), so the next
`npm install` pulls their code. Look-alikes of real packages are the classic typosquat.

1. `scripts/phantom_deps.py` (offline) lists imports that are **not declared** in the manifest and declared packages
   **missing from the lockfile** (never installed). Both are where invented names show up.
2. For each candidate and for any dependency added recently (`git log -p -- package.json requirements*.txt
   pyproject.toml`), check that the package is the intended one: the import resolves to a real, maintained project
   whose repository matches what the code expects. Querying the registry (`npm view <name>`, `pip index versions
   <name>`) is a network call: **ask the user first**.
3. Red flags: published very recently, few downloads, no repository link, install scripts, a name that is a plausible
   blend of two real packages.

Fix: remove the dependency, replace with the real package, pin versions and commit the lockfile (see `/sk-deps`).

## Triage

These patterns are cheap to confirm. Read 5–10 lines around each candidate; drop matches in tests, fixtures, seed data
that never runs in production, and documentation. Report the rest with the exact line and the one-line fix.

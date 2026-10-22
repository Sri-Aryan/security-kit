# SecurityKit

Security skills for AI coding agents. Install them into a project and ask Claude Code or OpenAI Codex to audit it:
`/sk-audit` for the whole project, `/sk-review` before each merge, `/sk-fix` to fix what was found.

- **Local only.** Your source code never leaves your machine. No telemetry, no accounts, no network calls.
- **Evidence, not guesses.** Scripts find candidates, the agent confirms each one in the code, and every finding
  cites `file:line`, a check ID, OWASP and CWE references, a fix and a regression test.
- **Concept-based.** Skills check security concepts (e.g. "is this query parameterized?"), so they work across
  languages and frameworks, guided by the OWASP Cheat Sheet Series.
- **Readable.** Plain Python and Node scripts with no dependencies to install. Nothing is obfuscated; read every line.

## Install

```bash
npx github:getsecuritykit/kit init
```

That's it: no questions. Every skill is installed once for your user, so it works in **every project** and for
**every agent**:

| Folder | Read by |
|---|---|
| `~/.claude/skills/` | Claude Code |
| `~/.codex/skills/` | OpenAI Codex |
| `~/.agents/skills/` | Other agents that support the open [Agent Skills](https://agentskills.io) format |

Each skill is a plain folder with a `SKILL.md`, so an agent that isn't listed can use it too: point it at
`~/.agents/skills/` (or paste a `SKILL.md` into its instructions).

To share the skills with your team instead, install them into the repository and commit them:

```bash
npx github:getsecuritykit/kit init --project    # ./.claude/skills, ./.codex/skills, ./.agents/skills
```

Requires Node.js 18+ and Python 3. [Semgrep](https://semgrep.dev) is optional; `/sk-api` uses it when present.

## Quick start

In your agent, inside the project:

```text
/sk-help      what to run first for this project, and every command
/sk-audit     audit the whole project → security-report-audit.md
/sk-review    review only your current changes
/sk-fix       fix findings one by one, with your approval
```

## Skills

Your agent can start the five **workflow** commands on its own from a plain request ("audit this project", "review
my change"). Every other skill runs when you type its command, or when you ask about one area ("check my JWT
handling") and `/sk-audit` picks the matching skill for you. In Claude Code, only the workflow descriptions are loaded
into every conversation (about 1 KB instead of 20 KB), so having SecurityKit installed costs almost nothing in
sessions that don't use it. (Codex doesn't read the `disable-model-invocation` setting, so it still lists every skill.)

<!-- catalog:start (generated from skills/catalog.json by tools/gen_catalog_docs.py; do not edit by hand) -->
### Workflows

*Start here: whole-project audits, everyday change reviews, and fixing what was found.*

| Command | What it does |
|---|---|
| `/sk-help` | Where to start for this project, then every SecurityKit command, grouped |
| `/sk-audit` | Run every relevant skill and produce one combined, deduplicated report and score |
| `/sk-review` | Fast security review of the current diff, branch or PR only |
| `/sk-fix` | Work through findings from any report, applying approved fixes with re-verification |
| `/sk-variant` | Variant analysis: turn one confirmed bug into a rule and find its siblings everywhere |

### APIs

*HTTP, REST, GraphQL, gRPC, real-time and webhook surfaces, and the contracts that describe them.*

| Command | What it does |
|---|---|
| `/sk-api` | API audit: auth and ownership on every endpoint, errors, validation, missing tests |
| `/sk-rest` | REST baseline: HTTPS, methods, content types, size limits, headers, CORS, errors |
| `/sk-graphql` | GraphQL: introspection, depth/cost limits, batching, field-level authorization |
| `/sk-openapi` | OpenAPI/Swagger spec vs code: undocumented and stale endpoints, auth mismatches |
| `/sk-webhooks` | Webhooks received (signatures, replay) and sent (SSRF, signing) |
| `/sk-websocket` | WebSockets, SSE and real-time: handshake auth, Origin, channel authorization, limits |
| `/sk-grpc` | gRPC: TLS, auth interceptors, per-method authorization, reflection, limits, deadlines |

### Identity & access

*Who the user is, how they prove it, and what they are allowed to do.*

| Command | What it does |
|---|---|
| `/sk-auth` | Login, sessions, MFA, enumeration, brute force, account recovery, SSO linking |
| `/sk-password` | Password hashing parameters, policy, change and reset flows, credential stuffing |
| `/sk-tokens` | JWT verification, token randomness and storage, refresh rotation, API keys |
| `/sk-oauth2` | OAuth 2.0 / OIDC: PKCE, state, redirect URIs, ID tokens, audiences, scopes |
| `/sk-saml` | SAML SSO: signature checks and wrapping, audience, replay, certificates, RelayState |
| `/sk-authprovider` | Clerk, Auth0, NextAuth, Better Auth, Supabase/Firebase Auth: trust, roles, webhooks |
| `/sk-passkeys` | Passkeys/WebAuthn, magic links and one-time codes: challenges, origins, tokens |
| `/sk-authz` | Access-control design: default deny, roles, tenant isolation, IDOR, escalation |

### Injection & untrusted input

*Every place user data reaches an interpreter, a browser, a URL fetcher or a parser.*

| Command | What it does |
|---|---|
| `/sk-validation` | Input validation: schemas, mass assignment, type confusion, ranges, allow-lists |
| `/sk-inject` | All injection: SQL, NoSQL, command, code, SSTI, LDAP, XPath, XXE, header, log |
| `/sk-xss` | Cross-site scripting: DOM sinks, escaping bypasses, sanitizers, CSP |
| `/sk-ssrf` | Server-side request forgery: URL fetches, private IPs, DNS rebinding, cloud metadata |
| `/sk-redirect` | Open redirects: next/returnUrl parameters, bypassable validation, login flows |
| `/sk-deserialize` | Unsafe deserialization (pickle, YAML, Java/.NET/PHP) and prototype pollution |
| `/sk-upload` | File uploads: type checks, names, size, storage, serving, presigned URLs, zip slip |

### Web & browser

*What the browser enforces, what the server tells it, and what caches and configs leak.*

| Command | What it does |
|---|---|
| `/sk-browser` | Security headers, clickjacking, cookie flags, tokens in storage, bundle secrets, SRI |
| `/sk-csrf` | CSRF: disabled protection, state-changing GETs, SameSite, CORS with credentials |
| `/sk-cache` | Caching: personal data cached publicly, cache poisoning and deception, shared keys |
| `/sk-config` | Misconfiguration: debug modes, stack traces, open actuators, fallback secrets |
| `/sk-nextjs` | Next.js, SvelteKit, Nuxt, Remix: Server Actions, middleware, RSC leaks, public env |
| `/sk-defaults` | Insecure defaults and fail-open: missing config, catch-allow, default-allow, nulls |

### Data, privacy & crypto

*Where data lives, who can read it, how it is protected, and what the logs say about it.*

| Command | What it does |
|---|---|
| `/sk-database` | Raw queries, row scoping, DB exposure, TLS, privileges and hardening |
| `/sk-privacy` | Personal data: minimization, exposure, third parties, consent, deletion, retention |
| `/sk-crypto` | Cryptography: algorithms, modes, IVs, keys and KDFs, randomness, TLS verification |
| `/sk-logging` | Security logging: events, audit trails, secrets in logs, alerting, retention |
| `/sk-baas` | Supabase/Firebase and other BaaS: RLS and rules, service keys, storage, functions |

### Business logic & abuse

*Money, limits, workflows and background work: the bugs scanners alone don't find.*

| Command | What it does |
|---|---|
| `/sk-business` | Business logic abuse: client-set prices, coupon reuse, skipped steps, limits |
| `/sk-race` | Race conditions: double spend, check-then-act, missing locks, idempotency |
| `/sk-payments` | Payments: server-side amounts, webhook verification, refunds, card data scope |
| `/sk-ratelimit` | Rate limits and quotas: login, OTP, expensive endpoints, IP spoofing, bypasses |
| `/sk-dos` | Resource exhaustion: body/page limits, ReDoS, zip bombs, timeouts, unbounded work |
| `/sk-email` | Email and SMS: header injection, poisoned links, spam relays, SMS pumping |
| `/sk-queue` | Queues and jobs: broker auth, unsafe serializers, worker authz, dashboards, DLQs |
| `/sk-abuse` | Abuse and fraud: bot sign-ups, CAPTCHA, trial and credit farming, free-tier costs |

### AI & agents

*LLM features, prompt injection, tool-using agents, MCP servers, retrieval and AI-written code.*

| Command | What it does |
|---|---|
| `/sk-ai` | LLM features vs OWASP LLM Top 10: unsafe output, leaks, PII, cost abuse, keys |
| `/sk-prompt-injection` | Prompt injection: untrusted channels, system prompts, tool approvals, outputs |
| `/sk-agents` | Agents and MCP: tool permissions, inputs, sandboxes, human approval, server trust |
| `/sk-rag` | RAG pipelines: poisoning, per-chunk access control, tenant isolation, vector stores |
| `/sk-ai-code` | AI-written code: placeholder auth, disabled checks, mass assignment, phantom packages |

### Apps & platforms

*Code that runs on users' devices: phones, desktops and browsers.*

| Command | What it does |
|---|---|
| `/sk-mobile` | Android/iOS (MASVS): storage, cleartext, TLS, exported components, WebViews |
| `/sk-electron` | Electron/Tauri: node integration, isolation, preload and IPC, openExternal, updates |
| `/sk-extension` | Browser extensions: permissions, remote code, message senders, content scripts |
| `/sk-game` | Games: server authority, leaderboards, economy, IAP and ad rewards, RPCs, client keys |

### Supply chain & infrastructure

*What ships with the code: dependencies, credentials, containers, clouds, pipelines and domains.*

| Command | What it does |
|---|---|
| `/sk-secrets` | Hardcoded and leaked secrets in code, config, git history, CI and images |
| `/sk-deps` | Dependencies: vulnerabilities, lockfiles, typosquats, confusion, install scripts |
| `/sk-docker` | Dockerfiles, Compose and Kubernetes: root, privileges, mounts, images, secrets |
| `/sk-cloud` | Cloud IaC: public buckets, wildcard IAM, open ports, encryption, IMDSv2, state |
| `/sk-paas` | Hosting platforms (Vercel, Netlify, Cloudflare, Render, Fly): secrets, previews, crons |
| `/sk-cicd` | CI/CD pipelines: triggers, script injection, token permissions, pinning, runners |
| `/sk-repo` | Repository hygiene: policy, CODEOWNERS, branch protection, tracked secrets, scans |
| `/sk-domain` | Domains and DNS: subdomain takeover, SPF/DKIM/DMARC, CAA, security.txt |

### Design, testing & assurance

*Threat models, tests and scans that prove controls work, and the evidence auditors ask for.*

| Command | What it does |
|---|---|
| `/sk-design` | Threat model: assets, trust boundaries, data flows, STRIDE per component |
| `/sk-tests` | Security test gaps (authn, authz, validation) and generation of the missing tests |
| `/sk-fuzz` | Property-based tests and fuzzing for parsers and input handlers |
| `/sk-dast` | Dynamic scan of a running app you own (OWASP ZAP), with confirmed findings |
| `/sk-asvs` | OWASP ASVS 5.0 coverage map at level 1-3, from all SecurityKit reports |
| `/sk-compliance` | Map findings to SOC 2, ISO 27001, PCI DSS, HIPAA and GDPR controls |
| `/sk-incident` | Incident readiness: plan, on-call, alerts, revocation, rotation, backups |
<!-- catalog:end -->

## How a skill works

1. **Inventory**: what the project has in this area (endpoints, queries, uploads, model calls, ...).
2. **Scan**: a local script finds candidate issues and writes `.securitykit/<area>-scan.json`.
3. **Confirm**: the agent reads the code behind each candidate and keeps only real issues, with evidence.
4. **Report**: a fixed template gives `security-report-<area>.md` plus `.securitykit/<area>-report.json`,
   with a score of 100 − 25×Critical − 10×High − 4×Medium − 1×Low.
5. **Optional**: `--tests` writes regression tests; `--fix` proposes fixes and applies only the ones you approve.

Dynamic checks (`--base-url`) only ever target localhost or a host you confirm you own.

**Reports stay out of git.** They list weaknesses that may not be fixed yet, so the first scan in a project writes
`.securitykit/.gitignore` (everything in it except `ignore.json` and `manifest.json`, which you can commit) and adds
`security-report*.md` to `.git/info/exclude`, which only affects your clone and leaves your `.gitignore` unchanged.
If reports were already committed, the scan warns you. To share a report on purpose, use `git add -f`.

## Token use and prompt caching

Your agent caches the conversation automatically: everything already in it (skill instructions, guides, scan
results) is re-billed at a tenth of the normal input price or less on later turns, as long as the start of the
conversation stays the same. SecurityKit is written to keep it that way: in Claude Code only the five workflow skills
put a description in every conversation (the others set `disable-model-invocation`), descriptions are short and fixed,
scanner output is byte-for-byte stable between runs, and skills read each file once. You can help:

- **Run related skills in one session.** `/sk-audit` then `/sk-fix` in the same conversation reuses everything
  already read; a new session starts cold.
- **Pick the model before a long run.** Switching models (or turning tools on and off) mid-audit discards the cache.
- **Don't update or edit installed skills mid-session.** The skill list is part of every request's prefix.
- **Answer questions promptly during interactive skills.** An idle cache expires (after five minutes by default;
  some plans keep it for an hour), and the next turn pays full price for the whole conversation again.

## Terminal commands

| Command | What it does |
|---|---|
| `npx github:getsecuritykit/kit skills` | Show every skill, grouped, with a one-line description (`--group ai`, `--json`) |
| `npx github:getsecuritykit/kit init` | Install every skill for every agent, for all projects (`--project` for this repo only) |
| `npx github:getsecuritykit/kit update` | Update installed skills; files you edited are kept and listed (`--project` too) |
| `npx github:getsecuritykit/kit list` | Show installed skills, versions and local edits |
| `npx github:getsecuritykit/kit doctor` | Check Node, Python, Semgrep and skill locations |

## Suppressing accepted risks

Add `securitykit-ignore: CHECK-ID` in a comment on (or above) the line, or an entry with a reason (and optional
expiry) in `.securitykit/ignore.json`. Entries without a reason are ignored.

## Limits

SecurityKit helps you find and fix common weaknesses; it is not a penetration test or a certification. A clean
report is not a guarantee of security.

## License

Proprietary. All rights reserved.

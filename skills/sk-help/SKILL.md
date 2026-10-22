---
name: sk-help
description: Shows where to start with SecurityKit for this project (detects the stack and recommends the first few commands) and lists every command grouped by area. Use when the user asks what SecurityKit can do, which security skills exist or where to start, or types /sk-help.
metadata:
  version: 0.1.0
  author: SecurityKit
---

# SecurityKit help

**Scope.** Shows a new user where to start: detects what this project is built with and recommends the first few SecurityKit commands for it, then lists the workflow commands and an index of every other group (workflows, APIs, identity and access, injection and input, web and browser, data/privacy/crypto, business logic, AI and agents, apps and platforms, supply chain and infrastructure, design/testing/assurance). `/sk-help all` prints every command with a one-line description and whether it is installed; `/sk-help <group>` prints one group.

The full list is too long to choose from on a first visit, so the default view is short. Never run scans or modify
files from this skill. The detection below only reads file names and manifests and prints to the chat.

`$SKILL` is the folder containing this file; the other skills are its sibling folders (`$SKILL/../sk-*`).
Use `python3` (or `python` / `py -3`).

## Which view

| Invocation | Show |
|---|---|
| `/sk-help` | **Start here** for this project, then the Workflows table, then the group index. |
| `/sk-help all` | Every group's full table (the tables below), then "Where to start", "Common options" and "Notes". |
| `/sk-help <group>` | That group's heading, intro and table only. Group IDs: `workflows`, `api`, `identity`, `input`, `web`, `data`, `logic`, `ai`, `apps`, `infra`, `design`; also accept a group's title or an obvious word ("auth", "injection", "docker"). |

In every table you print, fill the **Status** column with `✔ installed` or `not installed` by checking which
`sk-*` folders exist next to this skill's folder.

## Default view (`/sk-help`)

1. **Detect.** If the current folder looks like a project (it has source files or a manifest such as
   `package.json`, `pyproject.toml`, `go.mod`, `pom.xml`, `Gemfile`, `composer.json`, `*.csproj`), run
   `python3 $SKILL/../sk-audit/scripts/audit.py plan --root .` (no `--out`: it prints JSON and writes nothing).
   Skip this step, and say why in one line, if it is not a project, Python is missing, `sk-audit` is not installed
   or the command fails.
2. **Start here.** From the plan's `run` list, print:
   - `**Detected:**` one line naming the stack from the concrete evidence (e.g. "Express API, JWT auth, SQLite,
     outbound fetch()"). Use only rows whose evidence is a file or a match, not `always`.
   - `### Start here for this project` with **three** numbered commands (five at most), each with a short reason
     that cites its evidence: `1. /sk-authz: roles and ownership checks (db.js:7 has a role column)`.
     Pick skills with concrete evidence over `always` ones, and areas where one bug exposes other users' data or
     money (authz, auth, tokens, API, BaaS rules, payments, AI agents, uploads) over hardening (headers, logging,
     config). Add `/sk-secrets` last if there are fewer than three.
   - One line: `Or all of them at once: /sk-audit --quick (N skills apply to this project).`, with N = the length
     of `run`.
   - If `not_installed` is not empty: `Also relevant but not installed: sk-x, sk-y` and the command
     `npx github:getsecuritykit/kit init --skills sk-x,sk-y`.
   Without detection, print instead: `Run /sk-audit --quick for a first overview of the whole project, or
   /sk-review before your next commit.`
3. **Workflows.** Print the Workflows heading, intro and table from below.
4. **Index.** Print `### Everything else` and one line per remaining group, in the order below:
   `**APIs** (7): /sk-api, /sk-rest, /sk-graphql, ...`, listing every command in the group. Finish with:
   `Details: /sk-help <group> (e.g. /sk-help ai) · Everything: /sk-help all · Or just ask, e.g. "check my JWT
   handling": /sk-audit picks the matching skill.`
5. Print "Notes" (below) and stop. Don't print "Where to start" or "Common options" in this view.

<!-- catalog:start (generated from skills/catalog.json by tools/gen_catalog_docs.py; do not edit by hand) -->
### Workflows

*Start here: whole-project audits, everyday change reviews, and fixing what was found.*

| Command | What it does | Status |
|---|---|---|
| `/sk-help` | Where to start for this project, then every SecurityKit command, grouped | |
| `/sk-audit` | Run every relevant skill and produce one combined, deduplicated report and score | |
| `/sk-review` | Fast security review of the current diff, branch or PR only | |
| `/sk-fix` | Work through findings from any report, applying approved fixes with re-verification | |
| `/sk-variant` | Variant analysis: turn one confirmed bug into a rule and find its siblings everywhere | |

### APIs

*HTTP, REST, GraphQL, gRPC, real-time and webhook surfaces, and the contracts that describe them.*

| Command | What it does | Status |
|---|---|---|
| `/sk-api` | API audit: auth and ownership on every endpoint, errors, validation, missing tests | |
| `/sk-rest` | REST baseline: HTTPS, methods, content types, size limits, headers, CORS, errors | |
| `/sk-graphql` | GraphQL: introspection, depth/cost limits, batching, field-level authorization | |
| `/sk-openapi` | OpenAPI/Swagger spec vs code: undocumented and stale endpoints, auth mismatches | |
| `/sk-webhooks` | Webhooks received (signatures, replay) and sent (SSRF, signing) | |
| `/sk-websocket` | WebSockets, SSE and real-time: handshake auth, Origin, channel authorization, limits | |
| `/sk-grpc` | gRPC: TLS, auth interceptors, per-method authorization, reflection, limits, deadlines | |

### Identity & access

*Who the user is, how they prove it, and what they are allowed to do.*

| Command | What it does | Status |
|---|---|---|
| `/sk-auth` | Login, sessions, MFA, enumeration, brute force, account recovery, SSO linking | |
| `/sk-password` | Password hashing parameters, policy, change and reset flows, credential stuffing | |
| `/sk-tokens` | JWT verification, token randomness and storage, refresh rotation, API keys | |
| `/sk-oauth2` | OAuth 2.0 / OIDC: PKCE, state, redirect URIs, ID tokens, audiences, scopes | |
| `/sk-saml` | SAML SSO: signature checks and wrapping, audience, replay, certificates, RelayState | |
| `/sk-authprovider` | Clerk, Auth0, NextAuth, Better Auth, Supabase/Firebase Auth: trust, roles, webhooks | |
| `/sk-passkeys` | Passkeys/WebAuthn, magic links and one-time codes: challenges, origins, tokens | |
| `/sk-authz` | Access-control design: default deny, roles, tenant isolation, IDOR, escalation | |

### Injection & untrusted input

*Every place user data reaches an interpreter, a browser, a URL fetcher or a parser.*

| Command | What it does | Status |
|---|---|---|
| `/sk-validation` | Input validation: schemas, mass assignment, type confusion, ranges, allow-lists | |
| `/sk-inject` | All injection: SQL, NoSQL, command, code, SSTI, LDAP, XPath, XXE, header, log | |
| `/sk-xss` | Cross-site scripting: DOM sinks, escaping bypasses, sanitizers, CSP | |
| `/sk-ssrf` | Server-side request forgery: URL fetches, private IPs, DNS rebinding, cloud metadata | |
| `/sk-redirect` | Open redirects: next/returnUrl parameters, bypassable validation, login flows | |
| `/sk-deserialize` | Unsafe deserialization (pickle, YAML, Java/.NET/PHP) and prototype pollution | |
| `/sk-upload` | File uploads: type checks, names, size, storage, serving, presigned URLs, zip slip | |

### Web & browser

*What the browser enforces, what the server tells it, and what caches and configs leak.*

| Command | What it does | Status |
|---|---|---|
| `/sk-browser` | Security headers, clickjacking, cookie flags, tokens in storage, bundle secrets, SRI | |
| `/sk-csrf` | CSRF: disabled protection, state-changing GETs, SameSite, CORS with credentials | |
| `/sk-cache` | Caching: personal data cached publicly, cache poisoning and deception, shared keys | |
| `/sk-config` | Misconfiguration: debug modes, stack traces, open actuators, fallback secrets | |
| `/sk-nextjs` | Next.js, SvelteKit, Nuxt, Remix: Server Actions, middleware, RSC leaks, public env | |
| `/sk-defaults` | Insecure defaults and fail-open: missing config, catch-allow, default-allow, nulls | |

### Data, privacy & crypto

*Where data lives, who can read it, how it is protected, and what the logs say about it.*

| Command | What it does | Status |
|---|---|---|
| `/sk-database` | Raw queries, row scoping, DB exposure, TLS, privileges and hardening | |
| `/sk-privacy` | Personal data: minimization, exposure, third parties, consent, deletion, retention | |
| `/sk-crypto` | Cryptography: algorithms, modes, IVs, keys and KDFs, randomness, TLS verification | |
| `/sk-logging` | Security logging: events, audit trails, secrets in logs, alerting, retention | |
| `/sk-baas` | Supabase/Firebase and other BaaS: RLS and rules, service keys, storage, functions | |

### Business logic & abuse

*Money, limits, workflows and background work: the bugs scanners alone don't find.*

| Command | What it does | Status |
|---|---|---|
| `/sk-business` | Business logic abuse: client-set prices, coupon reuse, skipped steps, limits | |
| `/sk-race` | Race conditions: double spend, check-then-act, missing locks, idempotency | |
| `/sk-payments` | Payments: server-side amounts, webhook verification, refunds, card data scope | |
| `/sk-ratelimit` | Rate limits and quotas: login, OTP, expensive endpoints, IP spoofing, bypasses | |
| `/sk-dos` | Resource exhaustion: body/page limits, ReDoS, zip bombs, timeouts, unbounded work | |
| `/sk-email` | Email and SMS: header injection, poisoned links, spam relays, SMS pumping | |
| `/sk-queue` | Queues and jobs: broker auth, unsafe serializers, worker authz, dashboards, DLQs | |
| `/sk-abuse` | Abuse and fraud: bot sign-ups, CAPTCHA, trial and credit farming, free-tier costs | |

### AI & agents

*LLM features, prompt injection, tool-using agents, MCP servers, retrieval and AI-written code.*

| Command | What it does | Status |
|---|---|---|
| `/sk-ai` | LLM features vs OWASP LLM Top 10: unsafe output, leaks, PII, cost abuse, keys | |
| `/sk-prompt-injection` | Prompt injection: untrusted channels, system prompts, tool approvals, outputs | |
| `/sk-agents` | Agents and MCP: tool permissions, inputs, sandboxes, human approval, server trust | |
| `/sk-rag` | RAG pipelines: poisoning, per-chunk access control, tenant isolation, vector stores | |
| `/sk-ai-code` | AI-written code: placeholder auth, disabled checks, mass assignment, phantom packages | |

### Apps & platforms

*Code that runs on users' devices: phones, desktops and browsers.*

| Command | What it does | Status |
|---|---|---|
| `/sk-mobile` | Android/iOS (MASVS): storage, cleartext, TLS, exported components, WebViews | |
| `/sk-electron` | Electron/Tauri: node integration, isolation, preload and IPC, openExternal, updates | |
| `/sk-extension` | Browser extensions: permissions, remote code, message senders, content scripts | |
| `/sk-game` | Games: server authority, leaderboards, economy, IAP and ad rewards, RPCs, client keys | |

### Supply chain & infrastructure

*What ships with the code: dependencies, credentials, containers, clouds, pipelines and domains.*

| Command | What it does | Status |
|---|---|---|
| `/sk-secrets` | Hardcoded and leaked secrets in code, config, git history, CI and images | |
| `/sk-deps` | Dependencies: vulnerabilities, lockfiles, typosquats, confusion, install scripts | |
| `/sk-docker` | Dockerfiles, Compose and Kubernetes: root, privileges, mounts, images, secrets | |
| `/sk-cloud` | Cloud IaC: public buckets, wildcard IAM, open ports, encryption, IMDSv2, state | |
| `/sk-paas` | Hosting platforms (Vercel, Netlify, Cloudflare, Render, Fly): secrets, previews, crons | |
| `/sk-cicd` | CI/CD pipelines: triggers, script injection, token permissions, pinning, runners | |
| `/sk-repo` | Repository hygiene: policy, CODEOWNERS, branch protection, tracked secrets, scans | |
| `/sk-domain` | Domains and DNS: subdomain takeover, SPF/DKIM/DMARC, CAA, security.txt | |

### Design, testing & assurance

*Threat models, tests and scans that prove controls work, and the evidence auditors ask for.*

| Command | What it does | Status |
|---|---|---|
| `/sk-design` | Threat model: assets, trust boundaries, data flows, STRIDE per component | |
| `/sk-tests` | Security test gaps (authn, authz, validation) and generation of the missing tests | |
| `/sk-fuzz` | Property-based tests and fuzzing for parsers and input handlers | |
| `/sk-dast` | Dynamic scan of a running app you own (OWASP ZAP), with confirmed findings | |
| `/sk-asvs` | OWASP ASVS 5.0 coverage map at level 1-3, from all SecurityKit reports | |
| `/sk-compliance` | Map findings to SOC 2, ISO 27001, PCI DSS, HIPAA and GDPR controls | |
| `/sk-incident` | Incident readiness: plan, on-call, alerts, revocation, rotation, backups | |
<!-- catalog:end -->

## Where to start

- **Whole project:** `/sk-audit` picks the skills that apply, runs them, and writes one combined report.
- **Every change:** `/sk-review` checks just your diff before you commit or merge.
- **Fixing:** `/sk-fix` works through findings one by one, with your approval, and re-verifies each fix.
- **One area:** run any skill above directly, e.g. `/sk-inject` or `/sk-agents`, or just ask ("check my JWT
  handling") and `/sk-audit` picks the matching skill.
- **Not sure:** `/sk-help` with no arguments recommends the first three commands for this project.

## Common options

| Option | Meaning |
|---|---|
| `--section <name>` | Run one checklist section only (e.g. `/sk-api --section authz`). |
| `--tests` / `--write` | Also generate tests for what was found (audit skills; `/sk-tests`, `/sk-fuzz`). |
| `--fix` | Propose fixes one by one and apply only the ones you approve. |
| `--base-url <url>` | Add dynamic checks against a running app: localhost, or a host you confirm you own. |

Accepted risks can be suppressed with a `securitykit-ignore: <CHECK-ID>` comment or an entry with a reason in
`.securitykit/ignore.json`.

## Notes

- SecurityKit runs entirely on this machine. No code or results are sent anywhere.
- See the same list in a terminal with `npx github:getsecuritykit/kit skills`.
- Update the skills with `npx github:getsecuritykit/kit update` (files you edited are kept).
- Check the setup with `npx github:getsecuritykit/kit doctor`.
- A clean report is not a guarantee of security.

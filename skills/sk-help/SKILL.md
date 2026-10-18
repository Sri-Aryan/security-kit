---
name: sk-help
description: Lists every SecurityKit command grouped by area (workflows, APIs, identity and access, injection and input, web and browser, data/privacy/crypto, business logic, AI and agents, apps and platforms, supply chain and infrastructure, design/testing/assurance) with a one-line description of each and whether it is installed. Use when the user asks what SecurityKit can do, which security commands or skills exist, where to start, or types /sk-help.
metadata:
  version: 0.1.0
  author: SecurityKit
---

# SecurityKit help

Show the user the grouped command list below. Do not run any scans from this skill.

1. Check which `sk-*` skill folders exist next to this one (the folder that contains this skill). In the
   **Status** column write `✔ installed` or `not installed`.
2. Print each group as a level-3 heading (`### Workflows`), its one-line intro in italics, then its table, keeping
   the order below. With `/sk-help <group>` (e.g. `/sk-help ai`, `/sk-help api`), print only that group.
3. After the tables, print "Where to start", "Common options" and "Notes" exactly as written below.

<!-- catalog:start (generated from skills/catalog.json by tools/gen_catalog_docs.py; do not edit by hand) -->
### Workflows

*Start here: whole-project audits, everyday change reviews, and fixing what was found.*

| Command | What it does | Status |
|---|---|---|
| `/sk-help` | List every SecurityKit command, grouped, with a one-line description | |
| `/sk-audit` | Run every relevant skill and produce one combined, deduplicated report and score | |
| `/sk-review` | Fast security review of the current diff, branch or PR only | |
| `/sk-fix` | Work through findings from any report, applying approved fixes with re-verification | |

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

### Data, privacy & crypto

*Where data lives, who can read it, how it is protected, and what the logs say about it.*

| Command | What it does | Status |
|---|---|---|
| `/sk-database` | Raw queries, row scoping, DB exposure, TLS, privileges and hardening | |
| `/sk-privacy` | Personal data: minimization, exposure, third parties, consent, deletion, retention | |
| `/sk-crypto` | Cryptography: algorithms, modes, IVs, keys and KDFs, randomness, TLS verification | |
| `/sk-logging` | Security logging: events, audit trails, secrets in logs, alerting, retention | |

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

### AI & agents

*LLM features, prompt injection, tool-using agents, MCP servers and retrieval.*

| Command | What it does | Status |
|---|---|---|
| `/sk-ai` | LLM features vs OWASP LLM Top 10: unsafe output, leaks, PII, cost abuse, keys | |
| `/sk-prompt-injection` | Prompt injection: untrusted channels, system prompts, tool approvals, outputs | |
| `/sk-agents` | Agents and MCP: tool permissions, inputs, sandboxes, human approval, server trust | |
| `/sk-rag` | RAG pipelines: poisoning, per-chunk access control, tenant isolation, vector stores | |

### Apps & platforms

*Code that runs on users' devices: phones, desktops and browsers.*

| Command | What it does | Status |
|---|---|---|
| `/sk-mobile` | Android/iOS (MASVS): storage, cleartext, TLS, exported components, WebViews | |
| `/sk-electron` | Electron/Tauri: node integration, isolation, preload and IPC, openExternal, updates | |
| `/sk-extension` | Browser extensions: permissions, remote code, message senders, content scripts | |

### Supply chain & infrastructure

*What ships with the code: dependencies, credentials, containers, clouds, pipelines and domains.*

| Command | What it does | Status |
|---|---|---|
| `/sk-secrets` | Hardcoded and leaked secrets in code, config, git history, CI and images | |
| `/sk-deps` | Dependencies: vulnerabilities, lockfiles, typosquats, confusion, install scripts | |
| `/sk-docker` | Dockerfiles, Compose and Kubernetes: root, privileges, mounts, images, secrets | |
| `/sk-cloud` | Cloud IaC: public buckets, wildcard IAM, open ports, encryption, IMDSv2, state | |
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
- **One area:** run any skill above directly, e.g. `/sk-inject` or `/sk-agents`.

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

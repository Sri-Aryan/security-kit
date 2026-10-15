---
name: sk-help
description: Lists SecurityKit commands (sk-api and other sk-* security skills) and how to use them. Use when the user asks what SecurityKit can do, which security commands exist, or types /sk-help.
metadata:
  version: 0.1.0
---

# SecurityKit help

Print the table below for the user. Before printing, check which `sk-*` skill folders actually exist
next to this one (in `.claude/skills/` or `.codex/skills/`) and mark each row "installed" or "not installed".
Do not run any scans from this skill.

| Command | What it does | Status |
|---|---|---|
| `/sk-api` | Audits the project's APIs for security issues, error handling and missing tests. Writes `security-report.md` and `.securitykit/report.json`. | |
| `/sk-api --tests` | Same audit, plus generates API tests (auth, ownership/IDOR, validation, error codes) in the project's existing test framework. | |
| `/sk-api --fix` | Same audit, then proposes low-risk fixes one by one and applies only the ones the user approves. | |
| `/sk-api --section <name>` | Runs one checklist section only, e.g. `--section authz`. | |
| `/sk-api --base-url http://localhost:3000` | Adds dynamic HTTP checks against a running app (localhost, or a host the user confirms they own). | |
| `/sk-graphql` | Audits GraphQL APIs: introspection, depth/cost limits, batching and alias abuse, field- and object-level authorization, error leaks, CSRF. Writes `security-report-graphql.md`. | |
| `/sk-graphql --url http://localhost:4000/graphql` | Adds read-only probes against a running GraphQL endpoint. | |
| `/sk-webhooks` | Audits webhooks you receive (signature verification, raw body, replay, idempotency) and send (SSRF on user URLs, redirects, signing). Writes `security-report-webhooks.md`. | |
| `/sk-webhooks --url http://localhost:3000/webhooks/x` | Adds probes (unsigned / bad signature / oversized) against one receiver, after the user confirms. | |
| `/sk-openapi` | Compares the OpenAPI/Swagger spec with the code (undocumented, stale, auth mismatches) and lints the contract. Writes `security-report-openapi.md`. | |
| `/sk-help` | This list. | |

All audit commands accept `--section <name>`, `--tests` and `--fix`.

Coming later: `sk-auth`, `sk-secrets`, `sk-deps`, `sk-inject`, `sk-config`, `sk-mobile`, `sk-ai`, `sk-audit`.

Then add these notes:

- SecurityKit runs entirely on this machine. No code or results are sent anywhere.
- Update the skills with `npx github:getsecuritykit/kit update` (files the user edited are kept).
- Check the setup with `npx github:getsecuritykit/kit doctor`.
- A clean report is not a guarantee of security.

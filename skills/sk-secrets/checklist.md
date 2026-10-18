# Secrets exposure checklist

Source of truth for `sk-secrets` check IDs. A secret is any value that grants access: API keys, passwords,
tokens, private keys, signing secrets, connection strings, webhook secrets. Concepts apply to every
language and platform. `references/guide.md` explains each check and the rotation procedure.

Columns: **Mode** S = static. OWASP = OWASP Top 10 2021 / API Top 10 2023.

## Source code (CODE)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| SEC-CODE-001 | No secrets hardcoded in source code (keys, passwords, tokens, connection strings with credentials) | S | Critical | A07 | CWE-798 |
| SEC-CODE-002 | No secrets used as default / fallback values when an environment variable is missing | S | High | A05 | CWE-1188 |

## Configuration and environment files (CFG / ENV)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| SEC-CFG-001 | No secrets in committed configuration (YAML/JSON/properties/XML, docker-compose, Kubernetes manifests, Terraform vars, Helm values) | S | Critical | A05 | CWE-798 |
| SEC-ENV-001 | `.env` files with real values are not committed and are git-ignored; `.env.example` contains placeholders only | S | High | A05 | CWE-538 |

## Keys and history (KEY / GIT)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| SEC-KEY-001 | No private keys, certificates with keys, keystores or cloud credential files in the repository | S | Critical | A02 | CWE-321 |
| SEC-GIT-001 | No secrets in git history (a secret deleted in a later commit is still exposed) | S | High | A05 | CWE-540 |

## Client side (FRONT)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| SEC-FRONT-001 | No server secrets in code shipped to browsers or mobile apps (public env prefixes, service-role keys, bundled config) | S | Critical | A01 | CWE-200 |

## Build and delivery (CI / DOCKER)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| SEC-CI-001 | CI/CD pipelines take secrets from the platform's secret store and never echo, print or upload them | S | High | A05 | CWE-532 |
| SEC-DOCKER-001 | Container images do not bake in secrets (`ENV`/`ARG` with secrets, copied `.env`/key files, secrets left in layers) | S | High | A05 | CWE-538 |

## Runtime handling (LOG / MGMT)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| SEC-LOG-001 | Secrets and full environment/config objects are never logged or returned in errors | S | High | A09 | CWE-532 |
| SEC-MGMT-001 | Secrets are loaded at runtime from the environment or a secret manager and validated at startup (fail fast when missing) | S | Medium | A05 | CWE-1188 |
| SEC-MGMT-002 | Credentials follow least privilege (scoped cloud keys, read-only where possible, per-environment secrets) | S | Medium | A01 | CWE-272 |

## Process (PROC)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| SEC-PROC-001 | Every exposed secret is rotated (revoked and reissued), not just deleted from the code | S | Critical | A07 | CWE-798 |
| SEC-PROC-002 | Secret scanning runs before commit or in CI (pre-commit hook, CI step, platform push protection) | S | Low | A05 | CWE-540 |

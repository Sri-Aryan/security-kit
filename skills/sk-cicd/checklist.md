# CI/CD pipeline security checklist

Source of truth for `sk-cicd` check IDs. Concepts apply to any CI/CD system (GitHub Actions, GitLab CI,
Jenkins, CircleCI, Azure Pipelines, Bitbucket, Buildkite, Cloud Build…). Based on the OWASP CI/CD Security
and GitHub Actions Security cheat sheets and the OWASP Top 10 CI/CD Security Risks. `references/guide.md`
explains how to verify and fix each check.

Columns: **Mode** S = static (pipeline files and repo settings). OWASP = OWASP Top 10 2021.

## Triggers and untrusted code (TRIG)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| CICD-TRIG-001 | Untrusted code (forks, external PRs) never runs in a privileged context: no checkout/build of PR code under `pull_request_target`, `workflow_run` or equivalent with secrets or write tokens | S | Critical | A08 | CWE-829 |
| CICD-TRIG-002 | Comment- and label-triggered workflows verify the actor is authorized and bind to a specific commit SHA | S | High | A01 | CWE-863 |

## Injection (INJ)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| CICD-INJ-001 | Attacker-controlled values (PR/issue titles and bodies, branch names, commit messages, comments) are never interpolated into scripts; they are passed through environment variables | S | Critical | A03 | CWE-78 |

## Permissions and identity (PERM)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| CICD-PERM-001 | The pipeline token has least privilege: read-only (or none) by default, write granted per job only where needed | S | High | A01 | CWE-272 |
| CICD-PERM-002 | Cloud and registry access uses short-lived federated credentials (OIDC) scoped per job/environment, not long-lived keys | S | High | A07 | CWE-798 |

## Third-party code (DEP)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| CICD-DEP-001 | Third-party actions, orbs, plugins, reusable workflows and CI images are pinned immutably (full commit SHA / image digest) | S | High | A08 | CWE-829 |
| CICD-DEP-002 | Third-party CI components are minimized, vetted, and updated through Dependabot/Renovate (with a release cooldown) | S | Medium | A06 | CWE-1104 |
| CICD-DEP-003 | Dependency installs in CI enforce lockfiles and integrity (`npm ci`, `--frozen-lockfile`, `--require-hashes`) | S | Medium | A08 | CWE-494 |

## Secrets (SECRET)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| CICD-SECRET-001 | No secrets hardcoded in pipeline configuration; secrets come from the platform's secret store or a secrets manager | S | Critical | A07 | CWE-798 |
| CICD-SECRET-002 | Secrets are exposed minimally: step-level not job-level, no `secrets: inherit`, never echoed or traced, checkout does not persist credentials | S | High | A09 | CWE-532 |

## Execution environment (RUN)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| CICD-RUN-001 | Self-hosted runners are never used for public repositories or untrusted PRs, are ephemeral, and hold no sensitive data | S | Critical | A08 | CWE-829 |
| CICD-RUN-002 | Pipeline steps do not run privileged containers or mount the Docker socket | S | High | A05 | CWE-250 |
| CICD-RUN-003 | No remote scripts piped into a shell (`curl … | sh`) without integrity verification | S | High | A08 | CWE-494 |
| CICD-RUN-004 | Runner network egress is restricted or monitored | S | Low | A05 | CWE-923 |

## Artifacts (ART)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| CICD-ART-001 | Release and publish workflows do not restore caches or artifacts that untrusted workflows can write (cache/artifact poisoning) | S | High | A08 | CWE-345 |
| CICD-ART-002 | Release artifacts and images are signed, with provenance and an SBOM | S | Medium | A08 | CWE-345 |

## Deployment (DEPLOY)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| CICD-DEPLOY-001 | Production deployment requires approval (protected environments / manual gates) and runs only from protected branches or tags | S | High | A01 | CWE-284 |

## Source control (SCM)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| CICD-SCM-001 | Branch protection: required reviews that cannot be bypassed, required status checks, CODEOWNERS covering pipeline files, no unsafe auto-merge | S | High | A01 | CWE-284 |
| CICD-SCM-002 | Workflow runs from first-time or external contributors require approval | S | High | A08 | CWE-829 |
| CICD-SCM-003 | Commits are signed and verified before merge | S | Low | A08 | CWE-345 |

## Scanning, logging and AI (SCAN / LOG / AI)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| CICD-SCAN-001 | The pipeline runs security checks as required gates: SAST, dependency and secret scanning, IaC scanning, workflow linting | S | Medium | A06 | CWE-1104 |
| CICD-LOG-001 | Pipeline and SCM audit logs are retained centrally and contain no secrets | S | Low | A09 | CWE-778 |
| CICD-AI-001 | AI assistants/agents in CI have minimal tools and permissions and never combine untrusted input with secrets or write tokens | S | High | A08 | CWE-1427 |

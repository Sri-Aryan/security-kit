# Repository hygiene checklist

Source of truth for `sk-repo` check IDs. Covers the security of the source repository itself on any hosting platform
(GitHub, GitLab, Bitbucket, Azure DevOps, self-hosted): disclosure policy, code ownership, branch protection and
reviews, commit signing, `.gitignore` coverage, sensitive files committed, secret scanning and SAST, dependency update
automation, pull-request checks, and access to the repository. Pipeline internals: `sk-cicd`. Secrets in code and
history: `sk-secrets`. Based on the OWASP Software Supply Chain Security cheat sheet, OpenSSF Scorecard checks and
SLSA source requirements.

Columns: **Mode** S = static (local repo), M = manual (platform settings, ask the user). OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| REPO-POLICY-001 | A security policy (`SECURITY.md`) tells reporters how to disclose vulnerabilities privately | S | Low | A04 | CWE-1059 |
| REPO-OWNERS-001 | `CODEOWNERS` assigns reviewers, including for sensitive paths (CI workflows, auth, infrastructure, dependency manifests) | S | Medium | A04 | CWE-1220 |
| REPO-PROTECT-001 | The default and release branches are protected: required reviews (ideally from code owners), required status checks, no force-push or deletion, admins included | M | High | A08 | CWE-284 |
| REPO-SIGN-001 | Commits (or at least merges/tags) are signed and the platform verifies them | S+M | Low | A08 | CWE-345 |
| REPO-IGNORE-001 | `.gitignore` excludes secrets and local artifacts (`.env`, keys, certificates, state files, databases, dependency folders) | S | Medium | A05 | CWE-538 |
| REPO-TRACKED-001 | No sensitive files are tracked (env files, private keys, keystores, state files, database dumps, credential files) | S | High | A07 | CWE-540 |
| REPO-SCAN-001 | Secret scanning (pre-commit and/or CI, plus platform push protection) and static analysis run on every change | S+M | Medium | A06 | CWE-1104 |
| REPO-DEPS-001 | Dependency updates are automated (Dependabot, Renovate) | S | Low | A06 | CWE-1104 |
| REPO-CI-001 | CI runs tests and checks on pull/merge requests before merging | S | Medium | A04 | CWE-1059 |
| REPO-ACCESS-001 | Repository and organization access is least-privilege, MFA is enforced, and deploy keys/tokens are scoped and reviewed | M | High | A01 | CWE-284 |

#!/usr/bin/env python3
"""
SecurityKit repository hygiene check (local, read-only, standard library + the git CLI).

Looks at the repository itself, not the application: security policy, code owners, .gitignore coverage, sensitive
files tracked in git, commit signing on recent commits, secret scanning / SAST / dependency updates in CI or
pre-commit, and pull-request checks. Remote settings (branch protection, rulesets, required reviews) are not visible
locally and are listed as questions for the user.

  python3 repo_check.py --root . --out .securitykit/repo-check.json
"""

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys

from sk_outputs import prepare_output

VERSION = "0.1.0"

POLICY_PATHS = ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md", "SECURITY.txt", ".well-known/security.txt"]
OWNERS_PATHS = ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS", ".gitlab/CODEOWNERS"]
IGNORE_SHOULD = [".env", "*.pem", "*.key", "*.p12", "*.pfx", "*.tfstate", ".terraform/", "id_rsa", "*.sqlite", "node_modules/"]
SENSITIVE_TRACKED = [".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
                     "*.tfstate", "*.tfstate.backup", "*.kdbx", "*.sqlite", "*.sqlite3", "*.db", "*.dump", "*.sql.gz", "*.bak",
                     ".npmrc", ".pypirc", ".netrc", "credentials", "credentials.json", "service-account*.json", "*.ovpn", "kubeconfig", ".htpasswd"]
SAFE_TRACKED = [".env.example", ".env.sample", ".env.template", ".env.defaults", ".env.test"]
SCANNERS = r"(?i)(gitleaks|trufflehog|detect-secrets|git-secrets|ggshield|talisman|semgrep|codeql|github/codeql-action|snyk|trivy|osv-scanner|bandit|gosec|brakeman|njsscan|horusec|sonar|checkov|tfsec|kics|zizmor|dependency-review-action|securitykit)"
CI_GLOBS = [".github/workflows/*.yml", ".github/workflows/*.yaml", ".gitlab-ci.yml", ".circleci/config.yml", "azure-pipelines.yml", "Jenkinsfile", "bitbucket-pipelines.yml"]


def git(root, *args):
    r = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
    return r.stdout if r.returncode == 0 else None


def read(root, rel):
    try:
        with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as fh:
            return fh.read(500_000)
    except OSError:
        return ""


def first_existing(root, paths):
    return next((p for p in paths if os.path.isfile(os.path.join(root, p))), None)


def ci_files(root, tracked):
    files = [f for f in tracked if any(fnmatch.fnmatch(f, g) for g in CI_GLOBS)]
    return files or [g for g in CI_GLOBS if "*" not in g and os.path.isfile(os.path.join(root, g))]


def main(argv=None):
    ap = argparse.ArgumentParser(description="SecurityKit repository hygiene check.")
    ap.add_argument("--root", default=".")
    ap.add_argument("--commits", type=int, default=50, help="recent commits to check for signatures (default 50)")
    ap.add_argument("--out")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)
    ls = git(root, "ls-files", "-z")
    if ls is None:
        print("error: not a git repository (or git is not installed)", file=sys.stderr)
        return 2
    tracked = [f for f in ls.split("\0") if f]
    candidates = []

    def add(check, detail, file=None):
        candidates.append({"check": check, "file": file, "detail": detail})

    policy = first_existing(root, POLICY_PATHS)
    if not policy:
        add("REPO-POLICY-001", "no SECURITY.md (root, .github/ or docs/): reporters don't know how to disclose vulnerabilities")
    elif not re.search(r"(?i)(mailto:|@|security advisor|report|contact|https?://)", read(root, policy)):
        add("REPO-POLICY-001", "SECURITY.md has no reporting contact", policy)

    owners = first_existing(root, OWNERS_PATHS)
    if not owners:
        add("REPO-OWNERS-001", "no CODEOWNERS: sensitive paths (CI, auth, infra) can change without a designated reviewer")
    else:
        text = read(root, owners)
        has_default = re.search(r"(?m)^\*\s+\S", text)
        if os.path.isdir(os.path.join(root, ".github", "workflows")) and not has_default and ".github" not in text:
            add("REPO-OWNERS-001", "CODEOWNERS doesn't cover CI workflows (.github/)", owners)

    gitignore = read(root, ".gitignore")
    missing = [p for p in IGNORE_SHOULD if not re.search(r"(?m)^\s*/?" + re.escape(p.rstrip("/")).replace(r"\*", ".*") + r"/?\s*$", gitignore)
               and not (p == ".env" and re.search(r"(?m)^\s*\.env\*?\s*$|^\s*\*\.env\s*$", gitignore))]
    relevant = [p for p in missing if not (p == "node_modules/" and not os.path.isfile(os.path.join(root, "package.json")))
                and not (p in ("*.tfstate", ".terraform/") and not any(f.endswith(".tf") for f in tracked))]
    if relevant:
        add("REPO-IGNORE-001", ".gitignore doesn't cover: " + ", ".join(relevant), ".gitignore" if gitignore else None)

    for f in tracked:
        name = os.path.basename(f)
        if name in SAFE_TRACKED or "/test" in f.lower() or "fixture" in f.lower() or "example" in f.lower():
            continue
        if any(fnmatch.fnmatch(name, pat) for pat in SENSITIVE_TRACKED):
            add("REPO-TRACKED-001", f"sensitive-looking file is tracked in git: {f} (check its contents; if secret, rotate and purge from history)", f)

    sigs = git(root, "log", f"-{args.commits}", "--format=%G?")
    if sigs:
        flags = [s for s in sigs.split() if s]
        signed = sum(1 for s in flags if s in ("G", "U", "X", "Y", "R", "E"))
        if flags and signed < len(flags):
            add("REPO-SIGN-001", f"{len(flags) - signed} of the last {len(flags)} commits are unsigned")
    else:
        flags, signed = [], 0

    ci = ci_files(root, tracked)
    hooks = read(root, ".pre-commit-config.yaml") + read(root, ".husky/pre-commit") + read(root, "lefthook.yml") + read(root, ".lefthook.yml")
    ci_text = "\n".join(read(root, f) for f in ci)
    scanners = sorted({m.group(1).lower() for m in re.finditer(SCANNERS, ci_text + "\n" + hooks)})
    if not re.search(r"(?i)gitleaks|trufflehog|detect-secrets|git-secrets|ggshield|talisman", ci_text + hooks):
        add("REPO-SCAN-001", "no secret scanning in CI or pre-commit hooks (e.g. gitleaks, trufflehog, detect-secrets)")
    if not re.search(r"(?i)semgrep|codeql|snyk|bandit|gosec|brakeman|njsscan|sonar|securitykit", ci_text):
        add("REPO-SCAN-001", "no static security analysis in CI (e.g. Semgrep, CodeQL)")

    has_bot = any(f in tracked for f in (".github/dependabot.yml", ".github/dependabot.yaml", "renovate.json", "renovate.json5", ".github/renovate.json", ".renovaterc", ".renovaterc.json"))
    if not has_bot:
        add("REPO-DEPS-001", "no Dependabot or Renovate configuration")

    pr_checks = [f for f in ci if re.search(r"(?m)^\s*(pull_request|pull_request_target|merge_request_event|merge_group)\b|pull_request:|merge_requests", read(root, f))]
    if ci and not pr_checks:
        add("REPO-CI-001", "CI does not run on pull/merge requests: changes can merge without tests or scans")
    if not ci:
        add("REPO-CI-001", "no CI configuration found")

    result = {
        "tool": "securitykit-repo-check", "version": VERSION,
        "tracked_files": len(tracked), "security_policy": policy, "codeowners": owners,
        "commits_checked": len(flags), "commits_signed": signed, "ci_files": ci, "scanners_found": scanners,
        "update_bot": has_bot,
        "ask_user": ["Is the default branch protected (required reviews, required status checks, no force-push/deletion)?",
                     "Who has admin/maintainer rights on the repository and organization, and is MFA enforced?",
                     "Are repository secrets/environments restricted to protected branches?",
                     "Is secret scanning / push protection enabled on the hosting platform?"],
        "candidates": candidates,
    }
    text = json.dumps(result, indent=2)
    if args.out:
        prepare_output(args.out)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"{len(tracked)} tracked files, {len(candidates)} candidates -> {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

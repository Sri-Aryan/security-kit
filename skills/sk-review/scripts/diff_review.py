#!/usr/bin/env python3
"""
SecurityKit diff review helper (read-only, standard library only).

Works out what changed, then runs every installed SecurityKit scanner on just the changed files and keeps the
candidates that fall on added lines. Also lists removed lines that look like security controls, dependency changes
and security-sensitive files. Every result is a CANDIDATE for the agent to confirm.

  python3 diff_review.py --root .                      # uncommitted changes if any, else current branch vs main
  python3 diff_review.py --root . --base origin/main   # branch vs base (merge-base, like a PR)
  python3 diff_review.py --root . --staged             # staged changes only
  python3 diff_review.py --root . --range A..B         # explicit range

Never contacts a remote: fetch the base branch yourself first if you want it up to date.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

VERSION = "0.1.0"

# Removed lines that look like security controls (REVIEW-REMOVED-001).
CONTROL_RE = re.compile(
    r"(?i)(authenticat|authoriz|requireAuth|isAuthenticated|login_required|@PreAuthorize|@Secured|@RolesAllowed|\[Authorize|"
    r"permission|guard|policy|\bcan\(|ensure_?\w*owner|owner_?id|tenant_?id|csrf|xsrf|rate.?limit|throttl|limiter|"
    r"helmet|content-security-policy|\bcsp\b|strict-transport|x-frame-options|nosniff|httpOnly|sameSite|secure\s*:\s*true|"
    r"validat|sanitiz|escape|DOMPurify|bleach|safeParse|schema|allow_?list|allowlist|whitelist|"
    r"verify|signature|hmac|timingSafeEqual|compare_digest|constant.?time|"
    r"verify\s*=\s*True|rejectUnauthorized\s*:\s*true|ssl|tls|"
    r"parameteri[sz]|prepared|bind_?param|"
    r"audit|max_?(tokens|iterations|steps|size|length)|timeout|"
    r"approval|confirm|sandbox)"
)

# Files whose changes deserve a closer look, by category (REVIEW-* + which specialist skill to suggest).
SENSITIVE = [
    ("auth", r"(?i)(auth|login|logout|session|password|passwd|oauth|oidc|saml|sso|jwt|token|permission|polic(y|ies)|guard|rbac|acl|middleware)", "sk-auth / sk-tokens"),
    ("crypto", r"(?i)(crypt|cipher|hash|hmac|sign(ing|ature)|random|kms|keystore|cert)", "sk-tokens / sk-password"),
    ("payments", r"(?i)(payment|billing|checkout|stripe|invoice|refund|subscription|wallet)", "sk-payments"),
    ("upload", r"(?i)(upload|attachment|multer|storage|s3|bucket)", "sk-upload"),
    ("ci", r"(^|/)(\.github/workflows/|\.gitlab-ci|\.circleci/|azure-pipelines|Jenkinsfile|bitbucket-pipelines)", "sk-cicd"),
    ("container", r"(?i)(^|/)(Dockerfile|Containerfile|[^/]*compose[^/]*\.ya?ml$|k8s/|kubernetes/|helm/|charts/)", "sk-docker"),
    ("iac", r"(?i)\.(tf|tfvars|bicep)$|cloudformation|(^|/)(pulumi|cdk)\b", "sk-design"),
    ("deps", r"(?i)(^|/)(package\.json|requirements[^/]*\.txt|pyproject\.toml|Pipfile|go\.mod|Gemfile|pom\.xml|build\.gradle(\.kts)?|Cargo\.toml|composer\.json|[^/]*\.csproj)$", "sk-review (REVIEW-DEPS-001)"),
    ("config", r"(?i)(^|/)(\.env[^/]*|settings\.py|config/|application[^/]*\.(ya?ml|properties)|appsettings[^/]*\.json|nginx[^/]*\.conf|next\.config|vite\.config|cors)", "sk-rest"),
    ("database", r"(?i)(migration|schema\.(prisma|sql)|\.sql$|models?/|repositor(y|ies)/|dao/)", "sk-database"),
    ("ai", r"(?i)(llm|prompt|agent|openai|anthropic|rag|embedding|vector|mcp)", "sk-ai / sk-agents"),
    ("agent-config", r"(?i)(^|/)(\.mcp\.json|mcp\.json|\.claude/settings[^/]*\.json|\.codex/config\.toml|claude_desktop_config\.json)$", "sk-agents"),
    ("api-contract", r"(?i)(openapi|swagger)[^/]*\.(ya?ml|json)$|\.graphql$|schema\.gql$", "sk-openapi / sk-graphql"),
    ("baas", r"(?i)(^|/)(supabase/|firestore\.rules$|storage\.rules$|database\.rules\.json$|pb_migrations/|convex/)", "sk-baas"),
    ("platform", r"(?i)(^|/)(vercel\.json|netlify\.toml|_headers|_redirects|wrangler\.(toml|jsonc?)|render\.ya?ml|fly\.toml|railway\.(json|toml)|apphosting\.ya?ml)$", "sk-paas"),
    ("server-boundary", r"(?i)(^|/)(middleware|proxy)\.[cm]?[jt]s$|(^|/)actions?(/|\.[jt]s$)|(^|/)app/.*route\.[jt]s$|next\.config", "sk-nextjs"),
]
# Never review SecurityKit itself or its outputs: installed skills (with their rule examples), scan results, reports.
NOT_REVIEWED = re.compile(r"(^|/)\.(claude|codex|agents|cursor|gemini|windsurf|roo|continue|amazonq)/(skills|plugins|commands|agents)/"
                          r"|^\.securitykit/|^security-report[^/]*\.md$|^threat-model\.md$")
MANIFESTS = re.compile(SENSITIVE[7][1])
DEP_LINE = re.compile(r"""^\s*("(@?[\w./-]+)"\s*:\s*"[^"]*"|[A-Za-z0-9_.\-\[\]]+\s*(==|>=|<=|~=|!=|>|<|===)\s*[\w.*+-]+|[\w.-]+/[\w./-]+\s+v[\w.+-]+|gem\s+['"][\w-]+['"]|<artifactId>[\w.-]+</artifactId>|(implementation|api|compile)\s*\(?['"][\w.:-]+['"]|[\w-]+\s*=\s*("|\{)[^\n]*)""")


def git(root, *args):
    r = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()}")
    return r.stdout


def default_base(root):
    for ref in ("origin/main", "origin/master", "main", "master", "origin/develop", "develop"):
        try:
            git(root, "rev-parse", "--verify", "--quiet", ref)
            return ref
        except RuntimeError:
            continue
    return None


def choose_diff(root, args):
    """Return (description, git diff args, include_untracked, old_rev, new_rev).
    new_rev None = working tree, ":" = index."""
    diff = ["diff", "-U0", "--no-color", "--no-ext-diff"]
    if args.range:
        old, _, new = args.range.partition("..")
        return args.range, diff + [args.range], False, old.rstrip("."), new.lstrip(".") or "HEAD"
    if args.staged:
        return "staged changes", diff + ["--cached"], False, "HEAD", ":"
    base = args.base
    if not base:
        if git(root, "status", "--porcelain").strip():
            return "uncommitted changes vs HEAD", diff + ["HEAD"], True, "HEAD", None
        base = default_base(root)
        if not base:
            raise RuntimeError("no uncommitted changes and no main/master branch found; pass --base or --range")
    merge_base = git(root, "merge-base", base, "HEAD").strip()
    return f"{base}...HEAD", diff + [f"{base}...HEAD"], False, merge_base, "HEAD"


def read_rev(root, rev, path):
    """File content at a revision (None = working tree, ":" = index); "" if it does not exist there."""
    try:
        if rev is None:
            with open(os.path.join(root, path), encoding="utf-8", errors="replace") as fh:
                return fh.read()
        return git(root, "show", f"{rev}:{path}" if rev != ":" else f":{path}")
    except (RuntimeError, OSError):
        return ""


def json_deps(text):
    """{name: version} from package.json / composer.json content."""
    try:
        data = json.loads(text) if text.strip() else {}
    except ValueError:
        return {}
    deps = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "require", "require-dev"):
        if isinstance(data.get(key), dict):
            deps.update({k: str(v) for k, v in data[key].items()})
    return deps


def parse_diff(text):
    """{path: {"added": {new_line: text}, "removed": [(old_line, text)], "status": str}} from `git diff -U0`."""
    files, cur, new_ln, old_ln = {}, None, 0, 0
    for line in text.splitlines():
        if line.startswith("diff --git "):
            m = re.match(r"diff --git a/(.+?) b/(.+)$", line)
            cur = files.setdefault(m.group(2), {"added": {}, "removed": [], "status": "modified"}) if m else None
        elif cur is None:
            continue
        elif line.startswith("new file mode"):
            cur["status"] = "added"
        elif line.startswith("deleted file mode"):
            cur["status"] = "deleted"
        elif line.startswith("rename from"):
            cur["status"] = "renamed"
        elif line.startswith(("--- ", "+++ ", "index ", "similarity ", "rename to", "old mode", "new mode", "Binary files")):
            continue
        elif line.startswith("@@"):
            m = re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
            if m:
                old_ln, new_ln = int(m.group(1)), int(m.group(2))
        elif line.startswith("+"):
            cur["added"][new_ln] = line[1:]
            new_ln += 1
        elif line.startswith("-"):
            cur["removed"].append((old_ln, line[1:]))
            old_ln += 1
    return files


def add_untracked(root, files):
    out = git(root, "ls-files", "--others", "--exclude-standard", "-z")
    for rel in filter(None, out.split("\0")):
        full = os.path.join(root, rel)
        try:
            if os.path.getsize(full) > 2_000_000:
                continue
            with open(full, "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        if b"\x00" in data[:4096]:
            continue
        lines = data.decode("utf-8", "replace").splitlines()
        files[rel] = {"added": {i + 1: t for i, t in enumerate(lines)}, "removed": [], "status": "added (untracked)"}


def find_scanners(skills_dir):
    found = []
    for name in sorted(os.listdir(skills_dir)):
        script = os.path.join(skills_dir, name, "scripts", "sk_scan.py")
        if name.startswith("sk-") and os.path.isfile(script) and os.path.isdir(os.path.join(skills_dir, name, "rules")):
            found.append((name, script))
    return found


def run_scanners(root, scanners, changed, warnings):
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as fh:
        fh.write("\n".join(changed) + "\n")
        listing = fh.name
    results = []
    try:
        for skill, script in scanners:
            r = subprocess.run([sys.executable, script, "--root", root, "--only-files", listing, "--include-tests", "--agent-dirs"],
                               capture_output=True, text=True, encoding="utf-8", errors="replace")
            if r.returncode != 0:
                warnings.append(f"{skill}: scanner failed: {r.stderr.strip()[:200]}")
                continue
            try:
                data = json.loads(r.stdout)
            except ValueError:
                warnings.append(f"{skill}: scanner output was not JSON")
                continue
            for c in data.get("candidates", []):
                results.append({**c, "skill": skill})
    finally:
        os.unlink(listing)
    return results


def categorize(path):
    return [(cat, skills) for cat, rx, skills in SENSITIVE if re.search(rx, path)]


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="SecurityKit diff review helper.")
    ap.add_argument("--root", default=".")
    ap.add_argument("--base", help="base ref; reviews <base>...HEAD")
    ap.add_argument("--staged", action="store_true")
    ap.add_argument("--range", help="explicit git range, e.g. abc123..def456")
    ap.add_argument("--skills-dir", default=os.path.join(here, "..", ".."), help="folder holding the installed sk-* skills")
    ap.add_argument("--out")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)
    warnings = []
    try:
        desc, diff_args, untracked, old_rev, new_rev = choose_diff(root, args)
        files = parse_diff(git(root, *diff_args))
        if untracked:
            add_untracked(root, files)
        files = {p: f for p, f in files.items() if not NOT_REVIEWED.search(p)}
    except (RuntimeError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    changed = sorted(p for p, f in files.items() if f["added"] and os.path.isfile(os.path.join(root, p)))
    scanners = find_scanners(os.path.abspath(args.skills_dir))
    if not scanners:
        warnings.append("no installed SecurityKit scanners found next to sk-review; only diff heuristics ran")
    cands = run_scanners(root, scanners, changed, warnings) if changed and scanners else []

    in_diff, nearby = [], []
    for c in cands:
        f = files.get(c["file"])
        (in_diff if f and c["line"] in f["added"] else nearby).append(c)

    removed_controls, dependency_changes, file_rows = [], [], []
    for path, f in sorted(files.items()):
        cats = categorize(path)
        for old_ln, text in f["removed"]:
            if CONTROL_RE.search(text) and text.strip() and not text.strip().startswith(("//", "#", "*", "/*")):
                removed_controls.append({"file": path, "old_line": old_ln, "text": text.strip()[:240]})
        if MANIFESTS.search(path) and path.endswith(("package.json", "composer.json")):
            old, new = json_deps(read_rev(root, old_rev, path)), json_deps(read_rev(root, new_rev, path))
            added = [f"{k}: {v}" for k, v in sorted(new.items()) if old.get(k) != v]
            removed = [f"{k}: {v}" for k, v in sorted(old.items()) if k not in new]
            if added or removed:
                dependency_changes.append({"file": path, "added": added[:100], "removed": removed[:100]})
        elif MANIFESTS.search(path):
            added = [t.strip() for t in f["added"].values() if DEP_LINE.match(t)]
            removed = [t.strip() for _, t in f["removed"] if DEP_LINE.match(t)]
            if added or removed:
                dependency_changes.append({"file": path, "added": added[:100], "removed": removed[:100]})
        file_rows.append({
            "file": path, "status": f["status"], "added": len(f["added"]), "removed": len(f["removed"]),
            "categories": [c for c, _ in cats], "suggested_skills": sorted({s for _, s in cats}),
            "candidates_in_diff": sum(1 for c in in_diff if c["file"] == path),
        })

    result = {
        "tool": "securitykit-diff-review", "version": VERSION, "diff": desc,
        "totals": {"files": len(files), "added": sum(len(f["added"]) for f in files.values()),
                   "removed": sum(len(f["removed"]) for f in files.values()),
                   "sensitive_files": sum(1 for r in file_rows if r["categories"])},
        "scanners_run": [s for s, _ in scanners],
        "files": file_rows,
        "candidates_in_diff": in_diff,
        "candidates_elsewhere_in_changed_files": len(nearby),
        "removed_controls": removed_controls[:300],
        "dependency_changes": dependency_changes,
        "warnings": warnings,
    }
    text = json.dumps(result, indent=2)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"{desc}: {len(files)} files, {len(in_diff)} candidates on changed lines, "
              f"{len(removed_controls)} removed control lines -> {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

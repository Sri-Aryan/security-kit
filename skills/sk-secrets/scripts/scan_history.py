#!/usr/bin/env python3
"""
SecurityKit git-history secret scan (read-only, standard library only, needs `git`).

Applies the secret rules marked "history": true (rules/secrets.json) to every line ever *added* in the
repository's history (`git log -p --all`), and reports each distinct secret once: rule, file, commit,
date, whether it is still present in the working tree, and a redacted snippet.

Also reports .env-style files that are tracked by git, and whether .gitignore covers `.env`.

  python3 scan_history.py --root . [--max-commits 5000] [--out .securitykit/secrets-history.json]

Nothing leaves the machine; secret values are never printed (first 4 characters only).
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import sk_scan  # noqa: E402  (shipped next to this script)

ENV_FILE = re.compile(r"(^|/)\.env(\.[\w.-]+)?$|(^|/)[\w.-]+\.env$", re.I)
ENV_EXAMPLE = re.compile(r"\.(example|sample|template|dist|defaults?)$", re.I)


def git(root, *args, binary=False):
    r = subprocess.run(["git", "-C", root, *args], capture_output=True, timeout=600)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.decode("utf-8", "replace").strip() or f"git {' '.join(args)} failed")
    return r.stdout if binary else r.stdout.decode("utf-8", "replace")


def history_rules():
    rules = sk_scan.load_rules([os.path.join(HERE, "..", "rules")])
    return [r for r in rules if r.raw.get("history") and r.type == "match"]


def scan_history(root, max_commits):
    rules = history_rules()
    proc = subprocess.Popen(
        ["git", "-C", root, "log", "-p", "--all", "--no-color", "-U0", "--no-ext-diff", f"--max-count={max_commits}",
         "--format=@@@COMMIT %H %aI"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    found = {}
    commit = date = path = None
    new_line = 0
    commits = 0
    for raw in proc.stdout:
        line = raw.decode("utf-8", "replace").rstrip("\n")
        if line.startswith("@@@COMMIT "):
            _, commit, date = line.split(" ", 2)
            commits += 1
            continue
        if line.startswith("+++ "):
            path = None if line.endswith("/dev/null") else line[6:] if line.startswith("+++ b/") else line[4:]
            continue
        if line.startswith("@@ "):
            m = re.search(r"\+(\d+)", line)
            new_line = int(m.group(1)) if m else 0
            continue
        if not line.startswith("+") or line.startswith("+++") or path is None:
            continue
        text = line[1:]
        if len(text) > sk_scan.MAX_LINE or re.search(r"(\.lock|lock\.json|\.min\.js|\.svg)$", path):
            new_line += 1
            continue
        groups = sk_scan.file_groups(path)
        for rule in rules:
            if not rule.applies_to(path, groups):
                continue
            for _, m in sk_scan.match_rule_in_text(rule, text, [text]):
                g = 0 if rule.redact is True else int(rule.redact or 0)
                try:
                    value = m.group(g) or m.group(0)
                except IndexError:
                    value = m.group(0)
                key = (rule.id, hashlib.sha256(value.encode()).hexdigest())
                entry = found.get(key)
                occurrence = {"commit": commit[:12], "date": date, "file": path, "line": new_line}
                if entry is None:
                    found[key] = {
                        "rule": rule.id, "check_id": "SEC-GIT-001", "detected_as": rule.check_id, "title": rule.title,
                        "confidence": rule.confidence, "value_sha256": key[1][:16],
                        "snippet": sk_scan.redact(text, m, rule.redact or True).strip()[:240],
                        "first_seen": occurrence, "last_seen": occurrence, "occurrences": 1,
                        "_value": value,
                    }
                else:
                    entry["occurrences"] += 1
                    if date < entry["first_seen"]["date"]:
                        entry["first_seen"] = occurrence
                    if date > entry["last_seen"]["date"]:
                        entry["last_seen"] = occurrence
        new_line += 1
    proc.wait()
    return list(found.values()), commits


def still_present(root, findings):
    """Mark whether each secret value still appears in the tracked working tree."""
    tracked = [p for p in git(root, "ls-files", "-z").split("\0") if p]
    contents = {}
    for f in findings:
        f["in_working_tree"] = False
        for p in [f["last_seen"]["file"], f["first_seen"]["file"]] + tracked:
            if p not in contents:
                try:
                    with open(os.path.join(root, p), encoding="utf-8", errors="replace") as fh:
                        contents[p] = fh.read() if os.path.getsize(os.path.join(root, p)) < 2_000_000 else ""
                except OSError:
                    contents[p] = ""
            if f["_value"] in contents[p]:
                f["in_working_tree"] = True
                f["present_in"] = p
                break
        del f["_value"]


def env_checks(root):
    tracked = [p for p in git(root, "ls-files", "-z").split("\0") if p]
    out = {"tracked_env_files": [p for p in tracked if ENV_FILE.search(p) and not ENV_EXAMPLE.search(p)]}
    r = subprocess.run(["git", "-C", root, "check-ignore", "-q", ".env"], capture_output=True)
    out["dotenv_ignored"] = r.returncode == 0
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Scan git history for secrets (SecurityKit).")
    ap.add_argument("--root", default=".")
    ap.add_argument("--max-commits", type=int, default=5000)
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)
    try:
        git(root, "rev-parse", "--is-inside-work-tree")
    except (RuntimeError, OSError) as e:
        print(json.dumps({"git": "unavailable", "error": str(e)}))
        return 0
    findings, commits = scan_history(root, args.max_commits)
    still_present(root, findings)
    findings.sort(key=lambda f: (f["in_working_tree"], {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(f["confidence"], 3)))
    result = {
        "tool": "securitykit-secrets-history", "version": sk_scan.VERSION, "commits_scanned": commits,
        "max_commits": args.max_commits, "findings": findings,
        "history_only": sum(1 for f in findings if not f["in_working_tree"]),
        **env_checks(root),
        "note": "Every secret listed here must be rotated. Rewriting history does not un-leak it.",
    }
    text = json.dumps(result, indent=2)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"{commits} commits, {len(findings)} secrets ({result['history_only']} history-only) -> {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Keep SecurityKit's output out of git (standard library only).

Scan results in .securitykit/ and the security-report-*.md files describe weaknesses that may not be fixed yet, so
committing them by accident publishes a map of the project's holes. Every script calls prepare_output(path) before
writing a file. When the file goes into a .securitykit/ folder, or is a security-report*.md, it makes sure that:

- .securitykit/.gitignore exists and ignores everything except ignore.json (suppressions) and manifest.json (a
  project install), which teams are meant to commit;
- security-report*.md is ignored, via .git/info/exclude (local to this clone, so no tracked file changes), unless the
  project's own ignore rules already cover it;
- the user is told once if reports are already committed.

Nothing here is allowed to fail a scan: every problem is swallowed. Copied into each skill's scripts/ folder by
tools/sync_shared.py; edit shared/scripts/sk_outputs.py and re-run that tool.
"""

import fnmatch
import os
import subprocess
import sys

STATE_DIR = ".securitykit"
REPORT_GLOB = "security-report*.md"
STATE_GITIGNORE = (
    "# Written by SecurityKit. Scan results and reports describe weaknesses that may not be fixed yet, so they stay\n"
    "# out of git. Suppressions (ignore.json) and a project install's manifest.json are meant to be committed.\n"
    "*\n"
    "!ignore.json\n"
    "!manifest.json\n"
)
EXCLUDE_BLOCK = "# SecurityKit reports: they describe unfixed weaknesses (added by SecurityKit)\n" + REPORT_GLOB + "\n"
COMMITTABLE = {".securitykit/ignore.json", ".securitykit/manifest.json", ".securitykit/.gitignore"}


def prepare_output(path):
    """Create the folder for `path`; if it is SecurityKit output inside a project, keep it out of git."""
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    if os.path.basename(folder) == STATE_DIR:
        protect_project(os.path.dirname(folder))
    elif fnmatch.fnmatch(os.path.basename(path), REPORT_GLOB):
        protect_project(folder)


def protect_project(root):
    notes = []
    try:
        state = os.path.join(root, STATE_DIR)
        os.makedirs(state, exist_ok=True)
        gitignore = os.path.join(state, ".gitignore")
        if not os.path.exists(gitignore):
            with open(gitignore, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(STATE_GITIGNORE)
            notes.append(f"{STATE_DIR}/.gitignore")
    except OSError:
        return
    if _git(root, "rev-parse", "--is-inside-work-tree") != "true":
        _say(notes)
        return
    if _git_status(root, "check-ignore", "-q", "security-report-securitykit.md") == 1:
        exclude = _git(root, "rev-parse", "--git-path", "info/exclude")
        if exclude:
            exclude = os.path.join(root, exclude)
            try:
                existing = ""
                if os.path.exists(exclude):
                    with open(exclude, encoding="utf-8", errors="replace") as fh:
                        existing = fh.read()
                os.makedirs(os.path.dirname(exclude), exist_ok=True)
                with open(exclude, "a", encoding="utf-8", newline="\n") as fh:
                    fh.write(("\n" if existing and not existing.endswith("\n") else "") + EXCLUDE_BLOCK)
                notes.append(f"{REPORT_GLOB} in .git/info/exclude")
            except OSError:
                pass
    if notes:
        # First run in this project: also check nothing was committed before the protection existed.
        listed = _git(root, "ls-files", "--", REPORT_GLOB, STATE_DIR) or ""
        tracked = [f for f in listed.splitlines() if f and f not in COMMITTABLE]
        if tracked:
            shown = ", ".join(tracked[:5]) + (f" and {len(tracked) - 5} more" if len(tracked) > 5 else "")
            print(f"SecurityKit: warning: reports are already committed to git: {shown}. They describe weaknesses; "
                  f"consider `git rm --cached` on them (the files stay on disk).", file=sys.stderr)
    _say(notes)


def _say(notes):
    if notes:
        print(f"SecurityKit: keeping reports out of git ({', '.join(notes)})", file=sys.stderr)


def _run(root, args):
    try:
        return subprocess.run(["git", "-C", root] + list(args), capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None


def _git(root, *args):
    r = _run(root, args)
    return r.stdout.strip() if r is not None and r.returncode == 0 else None


def _git_status(root, *args):
    r = _run(root, args)
    return r.returncode if r is not None else None

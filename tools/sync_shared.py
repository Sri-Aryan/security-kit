#!/usr/bin/env python3
"""
Copy the shared scripts into the skills that use them:

- shared/scripts/sk_scan.py (the rule engine) into every skill that uses JSON rules (skills/*/rules/*.json), and
  into the skills in ENGINE_USERS that run the engine with rules they write at run time;
- shared/scripts/sk_outputs.py (keeps reports out of git) into every skill whose scripts import it, which
  includes every copy of the engine.

Skills are installed independently, so each ships its own copies. Run this after editing a shared script;
`--check` exits non-zero if any copy differs or is missing (used by the test suite).
"""

import filecmp
import glob
import os
import re
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHARED = os.path.join(ROOT, "shared", "scripts")
ENGINE = os.path.join(SHARED, "sk_scan.py")
OUTPUTS = os.path.join(SHARED, "sk_outputs.py")
ENGINE_USERS = {"sk-variant"}
IMPORTS_OUTPUTS = re.compile(r"^from sk_outputs import ", re.M)


def uses_engine(skill):
    return bool(glob.glob(os.path.join(skill, "rules", "*.json"))) or os.path.basename(skill) in ENGINE_USERS


def uses_outputs(skill):
    if uses_engine(skill):
        return True
    for script in glob.glob(os.path.join(skill, "scripts", "*.py")):
        if os.path.basename(script) == "sk_outputs.py":
            continue
        with open(script, encoding="utf-8") as fh:
            if IMPORTS_OUTPUTS.search(fh.read()):
                return True
    return False


def targets():
    for skill in sorted(glob.glob(os.path.join(ROOT, "skills", "sk-*"))):
        if uses_engine(skill):
            yield ENGINE, os.path.join(skill, "scripts", "sk_scan.py")
        if uses_outputs(skill):
            yield OUTPUTS, os.path.join(skill, "scripts", "sk_outputs.py")


def main():
    check = "--check" in sys.argv
    stale = []
    for src, dest in targets():
        if os.path.exists(dest) and filecmp.cmp(src, dest, shallow=False):
            continue
        stale.append(os.path.relpath(dest, ROOT))
        if not check:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copyfile(src, dest)
    if check and stale:
        print("shared script copies out of date (run tools/sync_shared.py):\n  " + "\n  ".join(stale))
        return 1
    print(("up to date" if check else f"synced {len(stale)} cop{'y' if len(stale) == 1 else 'ies'}") if stale or check else "up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())

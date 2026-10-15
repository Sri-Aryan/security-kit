#!/usr/bin/env python3
"""
Copy shared/scripts/sk_scan.py into every skill that uses JSON rules (skills/*/rules/*.json).

Skills are installed independently, so each ships its own copy of the engine. Run this after editing
the engine; `--check` exits non-zero if any copy differs (used by the test suite).
"""

import filecmp
import glob
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(ROOT, "shared", "scripts", "sk_scan.py")


def targets():
    for skill in sorted(glob.glob(os.path.join(ROOT, "skills", "sk-*"))):
        if glob.glob(os.path.join(skill, "rules", "*.json")):
            yield os.path.join(skill, "scripts", "sk_scan.py")


def main():
    check = "--check" in sys.argv
    stale = []
    for dest in targets():
        if os.path.exists(dest) and filecmp.cmp(ENGINE, dest, shallow=False):
            continue
        stale.append(os.path.relpath(dest, ROOT))
        if not check:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copyfile(ENGINE, dest)
    if check and stale:
        print("engine copies out of date (run tools/sync_shared.py):\n  " + "\n  ".join(stale))
        return 1
    print(("up to date" if check else f"synced {len(stale)} cop{'y' if len(stale) == 1 else 'ies'}") if stale or check else "up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())

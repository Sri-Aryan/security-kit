#!/usr/bin/env python3
"""
Build skills/<skill>/rules/<name>.json from tools/rules_src/<name>.py.

Rules are authored in Python (raw strings keep regexes readable) and shipped as JSON so the runtime
engine (sk_scan.py) needs nothing but the standard library. Each source module defines:
  SKILL = "sk-auth";  MACROS = {...} (optional, merged over common.MACROS);  RULES = [ {...}, ... ]
Then runs each skill's self-test.

  python tools/build_rules.py            # build all, run self-tests
  python tools/build_rules.py --check    # fail if any JSON is stale (used by tests)
"""

import importlib.util
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "tools", "rules_src")
sys.path.insert(0, SRC)
import common  # noqa: E402


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(SRC, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build():
    check = "--check" in sys.argv
    stale, built = [], []
    for f in sorted(os.listdir(SRC)):
        if not f.endswith(".py") or f in ("common.py", "__init__.py"):
            continue
        name = f[:-3]
        mod = load(name)
        macros = {**common.MACROS, **getattr(mod, "MACROS", {})}
        used = {m for r in mod.RULES for m in common_macros_used(r, macros)}
        data = {
            "_generated": f"from tools/rules_src/{f}; edit the source and run tools/build_rules.py",
            "macros": {k: v for k, v in macros.items() if k in used},
            "rules": mod.RULES,
        }
        text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
        dest = os.path.join(ROOT, "skills", mod.SKILL, "rules", f"{name}.json")
        current = open(dest, encoding="utf-8").read() if os.path.exists(dest) else None
        if current != text:
            stale.append(os.path.relpath(dest, ROOT))
            if not check:
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(text)
        built.append((mod.SKILL, dest))
    if check:
        if stale:
            print("stale rule JSON (run tools/build_rules.py):\n  " + "\n  ".join(stale))
            return 1
        print("rules up to date")
        return 0
    print(f"built {len(built)} rule file(s), {len(stale)} changed")
    # self-test every skill with the shared engine
    engine = os.path.join(ROOT, "shared", "scripts", "sk_scan.py")
    failed = False
    for skill, dest in built:
        r = subprocess.run([sys.executable, engine, "--rules", dest, "--self-test"], capture_output=True, text=True)
        checklist = os.path.join(ROOT, "skills", skill, "checklist.md")
        # the engine looks for ../checklist.md relative to itself, so re-run with the skill's copy if present
        skill_engine = os.path.join(ROOT, "skills", skill, "scripts", "sk_scan.py")
        if os.path.exists(skill_engine) and os.path.exists(checklist):
            r = subprocess.run([sys.executable, skill_engine, "--self-test"], capture_output=True, text=True)
        print(f"[{skill}] {r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr.strip()}")
        if r.returncode != 0:
            failed = True
            print(r.stdout + r.stderr)
    return 1 if failed else 0


def common_macros_used(rule, macros, seen=None):
    """Macro names referenced by a rule, following nested macros."""
    import re
    seen = set() if seen is None else seen
    text = json.dumps(rule)
    todo = set(re.findall(r"\{\{(\w+)\}\}", text))
    while todo:
        m = todo.pop()
        if m in seen or m not in macros:
            continue
        seen.add(m)
        todo |= set(re.findall(r"\{\{(\w+)\}\}", macros[m]))
    return seen


if __name__ == "__main__":
    sys.exit(build())

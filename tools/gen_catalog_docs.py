#!/usr/bin/env python3
"""
Write the grouped skill list from skills/catalog.json into README.md and skills/sk-help/SKILL.md, between the
markers <!-- catalog:start ... --> and <!-- catalog:end -->. Also checks the catalog covers every skills/sk-* folder
exactly once and that summaries fit on one line.

  python tools/gen_catalog_docs.py           # rewrite both files
  python tools/gen_catalog_docs.py --check   # exit 1 if they are out of date or the catalog is incomplete
"""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
START = "<!-- catalog:start (generated from skills/catalog.json by tools/gen_catalog_docs.py; do not edit by hand) -->"
END = "<!-- catalog:end -->"
BLOCK = re.compile(r"<!-- catalog:start[^>]*-->.*?<!-- catalog:end -->", re.S)
MAX_SUMMARY = 90


def load():
    with open(os.path.join(ROOT, "skills", "catalog.json"), encoding="utf-8") as fh:
        catalog = json.load(fh)
    folders = sorted(d for d in os.listdir(os.path.join(ROOT, "skills"))
                     if d.startswith("sk-") and os.path.isfile(os.path.join(ROOT, "skills", d, "SKILL.md")))
    names = [s["name"] for g in catalog["groups"] for s in g["skills"]]
    problems = []
    problems += [f"{n}: listed more than once" for n in sorted({n for n in names if names.count(n) > 1})]
    problems += [f"{n}: has a folder but is not in catalog.json" for n in folders if n not in names]
    problems += [f"{n}: in catalog.json but has no skills/{n}/SKILL.md" for n in names if n not in folders]
    problems += [f"{s['name']}: summary longer than {MAX_SUMMARY} characters" for g in catalog["groups"]
                 for s in g["skills"] if len(s["summary"]) > MAX_SUMMARY]
    return catalog, problems


def render(catalog, status_column):
    out = []
    for g in catalog["groups"]:
        out += [f"### {g['title']}", "", f"*{g['blurb']}*", ""]
        if status_column:
            out += ["| Command | What it does | Status |", "|---|---|---|"]
            out += [f"| `/{s['name']}` | {s['summary']} | |" for s in g["skills"]]
        else:
            out += ["| Command | What it does |", "|---|---|"]
            out += [f"| `/{s['name']}` | {s['summary']} |" for s in g["skills"]]
        out.append("")
    return "\n".join([START] + out[:-1] + [END])


def main():
    check = "--check" in sys.argv[1:]
    catalog, problems = load()
    for p in problems:
        print("catalog:", p)
    targets = [(os.path.join(ROOT, "README.md"), False), (os.path.join(ROOT, "skills", "sk-help", "SKILL.md"), True)]
    stale = []
    for path, status in targets:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        if not BLOCK.search(text):
            problems.append(f"{os.path.relpath(path, ROOT)}: catalog markers missing")
            continue
        new = BLOCK.sub(lambda _m: render(catalog, status), text, count=1)
        if new != text:
            stale.append(os.path.relpath(path, ROOT))
            if not check:
                with open(path, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(new)
    if check:
        for s in stale:
            print("out of date:", s, "(run python tools/gen_catalog_docs.py)")
        return 1 if stale or problems else 0
    print(f"updated: {', '.join(stale) or 'nothing (already current)'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

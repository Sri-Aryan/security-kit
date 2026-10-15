#!/usr/bin/env python3
"""
Convert raw `semgrep --json` output into SecurityKit candidates.

  { "semgrep": "ok"|"error", "version", "results": [ {check_id, rule, file, line, end_line,
    severity, confidence, message, snippet} ], "counts_by_check": {...}, "errors": [...] }

Snippets are read from the files on disk (newer Semgrep versions omit matched lines unless
logged in). Paths are relative to --root with forward slashes. Standard library only.
"""

import argparse
import json
import os
import sys

MAX_SNIPPET_LINES = 12


def read_lines(path, cache={}):
    if path not in cache:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                cache[path] = fh.read().splitlines()
        except OSError:
            cache[path] = []
    return cache[path]


def snippet(path, start, end):
    lines = read_lines(path)
    end = min(end, start + MAX_SNIPPET_LINES - 1, len(lines))
    return "\n".join(f"{n:>5} | {lines[n - 1]}" for n in range(start, end + 1))


def convert(raw, root):
    root = os.path.abspath(root)
    results = []
    for r in raw.get("results", []):
        meta = r.get("extra", {}).get("metadata", {}) or {}
        path = r["path"]
        abs_path = path if os.path.isabs(path) else os.path.join(os.getcwd(), path)
        rel = os.path.relpath(abs_path, root).replace(os.sep, "/")
        start, end = r["start"]["line"], r["end"]["line"]
        results.append({
            "check_id": meta.get("check_id", "UNMAPPED"),
            "rule": r.get("check_id", "").split(".")[-1],
            "file": rel,
            "line": start,
            "end_line": end,
            "severity": r.get("extra", {}).get("severity"),
            "confidence": meta.get("confidence"),
            "cwe": meta.get("cwe"),
            "owasp": meta.get("owasp"),
            "message": " ".join((r.get("extra", {}).get("message") or "").split()),
            "snippet": snippet(abs_path, start, end),
        })
    results.sort(key=lambda x: (x["check_id"], x["file"], x["line"]))
    counts = {}
    for x in results:
        counts[x["check_id"]] = counts.get(x["check_id"], 0) + 1
    errors = [
        {"type": e.get("type"), "message": " ".join(str(e.get("message", "")).split())[:300],
         "path": e.get("path")}
        for e in raw.get("errors", [])
    ]
    return {
        "semgrep": "ok",
        "version": raw.get("version"),
        "results": results,
        "counts_by_check": dict(sorted(counts.items())),
        "errors": errors,
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("semgrep_json")
    ap.add_argument("--root", default=".")
    ap.add_argument("--stderr-file", help="semgrep stderr, included if parsing fails")
    args = ap.parse_args(argv)
    try:
        with open(args.semgrep_json, encoding="utf-8-sig") as fh:
            raw = json.load(fh)
    except (OSError, ValueError) as exc:
        detail = ""
        if args.stderr_file and os.path.exists(args.stderr_file):
            with open(args.stderr_file, encoding="utf-8-sig", errors="replace") as fh:
                detail = fh.read()[-2000:]
        print(json.dumps({"semgrep": "error", "results": [], "error": f"could not read semgrep output: {exc}",
                          "stderr": detail}, indent=2))
        return 0
    print(json.dumps(convert(raw, args.root), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

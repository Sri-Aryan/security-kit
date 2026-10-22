#!/usr/bin/env python3
"""
SecurityKit variant analysis helper (read-only on the project, standard library only).

One confirmed bug is evidence of a pattern. This helper turns a pattern into a sweep:

  python3 variant.py seeds --root .                         # confirmed, unfixed findings from .securitykit/*report.json
  python3 variant.py sweep --root . --rules .securitykit/variant-rules.json [--seed src/a.ts:42] [--semgrep rule.yml]

`sweep` loads the rules (SecurityKit rule format, see sk_scan.py), proves each one against its own examples (the seed
must match, the fixed version must not), scans the project with the bundled engine, optionally runs a local Semgrep
rule, and labels every hit: `seed` (the original), `known` (already in a SecurityKit report) or `new`. Every hit is a
CANDIDATE that the agent confirms by reading the code.
"""

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import sk_scan  # noqa: E402  (bundled copy of the SecurityKit rule engine)

from sk_outputs import prepare_output

VERSION = "0.1.0"
LINE_SLACK = 3
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def load_reports(root):
    out = []
    for path in sorted(glob.glob(os.path.join(root, ".securitykit", "*report.json"))):
        if os.path.basename(path) in ("audit-report.json", "variant-report.json"):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        tool = data.get("tool") or {}
        if tool.get("name") != "SecurityKit" or not isinstance(data.get("findings"), list):
            continue
        for f in data["findings"]:
            loc = f.get("location") or {}
            out.append({
                "skill": tool.get("skill"), "report": os.path.relpath(path, root).replace(os.sep, "/"),
                "check_id": f.get("checkId") or f.get("check_id"), "severity": f.get("severity"), "title": f.get("title"),
                "file": loc.get("file") or f.get("file"), "line": loc.get("line") or f.get("line"),
                "fixed": bool(f.get("fixed")),
            })
    return out


def cmd_seeds(args):
    findings = [f for f in load_reports(args.root) if not f["fixed"] and f["file"]]
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["check_id"] or "", f["file"] or ""))
    result = {"tool": "securitykit-variant-seeds", "version": VERSION, "seeds": findings}
    return emit(result, args.out, f"{len(findings)} candidate seed(s)")


def parse_loc(text):
    m = re.match(r"^(.*?):(\d+)$", text.strip())
    return (m.group(1).replace("\\", "/"), int(m.group(2))) if m else (text.strip().replace("\\", "/"), None)


def near(a_file, a_line, b_file, b_line):
    if not a_file or not b_file or a_file.lstrip("./") != b_file.lstrip("./"):
        return False
    return a_line is None or b_line is None or abs(int(a_line) - int(b_line)) <= LINE_SLACK


def run_semgrep(root, config, warnings):
    exe = shutil.which("semgrep")
    if not exe:
        warnings.append("semgrep not installed: --semgrep skipped")
        return []
    r = subprocess.run([exe, "scan", "--config", config, "--json", "--metrics=off", "--quiet", "--disable-version-check", root],
                       capture_output=True, text=True)
    try:
        data = json.loads(r.stdout or "{}")
    except ValueError:
        warnings.append("semgrep output could not be parsed: " + (r.stderr or "")[:300])
        return []
    out = []
    for res in data.get("results", []):
        meta = (res.get("extra") or {}).get("metadata") or {}
        out.append({
            "rule": "semgrep:" + res.get("check_id", "?"), "check_id": meta.get("check_id") or "VARIANT-MATCH-001",
            "title": (res.get("extra") or {}).get("message", "")[:160],
            "file": os.path.relpath(os.path.join(root, res.get("path", "")), root).replace(os.sep, "/"),
            "line": (res.get("start") or {}).get("line"), "snippet": ((res.get("extra") or {}).get("lines") or "").strip()[:240],
            "confidence": meta.get("confidence", "MEDIUM"), "note": "",
        })
    for err in data.get("errors", [])[:5]:
        warnings.append("semgrep: " + str(err.get("message", err))[:200])
    return out


def cmd_sweep(args):
    rules = sk_scan.load_rules(args.rules) if args.rules else []
    bad_ids = [r.id for r in rules if not re.fullmatch(sk_scan.CHECK_ID, r.check_id)]
    if bad_ids:
        print("error: rules with malformed check_id: " + ", ".join(bad_ids), file=sys.stderr)
        return 2
    checked, failures = sk_scan.self_test(rules) if rules else (0, [])
    if failures:
        for f in failures:
            print("FAIL", f, file=sys.stderr)
        print(f"error: {len(failures)} rule example(s) failed; fix the rule before sweeping "
              "(the seed snippet must match and the fixed snippet must not)", file=sys.stderr)
        return 1
    if not rules and not args.semgrep:
        print("error: pass --rules and/or --semgrep", file=sys.stderr)
        return 2

    warnings = []
    cands = []
    if rules:
        res = sk_scan.scan(args.root, rules, include_tests=args.include_tests)
        cands += res["candidates"]
        warnings += res["warnings"]
    if args.semgrep:
        cands += run_semgrep(args.root, args.semgrep, warnings)

    seeds = [parse_loc(s) for s in args.seed]
    known = [f for f in load_reports(args.root) if f["file"]]
    seen = set()
    out = []
    for c in cands:
        key = (c["file"], c["line"])
        if key in seen:
            continue
        seen.add(key)
        if any(near(c["file"], c["line"], f, l) for f, l in seeds):
            c["status"] = "seed"
        else:
            hit = next((k for k in known if near(c["file"], c["line"], k["file"], k["line"])), None)
            if hit:
                c["status"] = "known"
                c["known_in"] = f"{hit['report']} [{hit['check_id']}]" + (" (fixed)" if hit["fixed"] else "")
            else:
                c["status"] = "new"
        out.append(c)
    out.sort(key=lambda c: ({"new": 0, "known": 1, "seed": 2}[c["status"]], c.get("file") or "", c.get("line") or 0))
    seeds_found = sum(1 for c in out if c["status"] == "seed")
    if seeds and seeds_found < len(seeds):
        warnings.append(f"only {seeds_found} of {len(seeds)} seed location(s) matched: the rule may be too narrow")
    counts = {s: sum(1 for c in out if c["status"] == s) for s in ("new", "known", "seed")}
    result = {"tool": "securitykit-variant-sweep", "version": VERSION, "rules": len(rules), "examples_checked": checked,
              "semgrep": bool(args.semgrep), "counts": counts, "candidates": out, "warnings": warnings}
    return emit(result, args.out, f"new {counts['new']} · known {counts['known']} · seed {counts['seed']}")


def emit(result, out_path, summary):
    text = json.dumps(result, indent=2)
    if out_path:
        prepare_output(out_path)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"{summary} → {out_path}")
    else:
        print(text)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="SecurityKit variant analysis helper.")
    ap.add_argument("--version", action="version", version=VERSION)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("seeds", help="list confirmed, unfixed findings from SecurityKit reports")
    s.add_argument("--root", default=".")
    s.add_argument("--out")
    w = sub.add_parser("sweep", help="self-test variant rules, scan, and label hits seed/known/new")
    w.add_argument("--root", default=".")
    w.add_argument("--rules", action="append", default=[], help="SecurityKit rule file (JSON); repeatable")
    w.add_argument("--semgrep", help="local Semgrep rule file to run as well (optional; needs semgrep installed)")
    w.add_argument("--seed", action="append", default=[], help="original location file:line; repeatable")
    w.add_argument("--include-tests", action="store_true")
    w.add_argument("--out")
    args = ap.parse_args(argv)
    if not os.path.isdir(args.root):
        print(f"error: not a directory: {args.root}", file=sys.stderr)
        return 2
    try:
        return cmd_seeds(args) if args.cmd == "seeds" else cmd_sweep(args)
    except (OSError, ValueError, re.error) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

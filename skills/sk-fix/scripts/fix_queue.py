#!/usr/bin/env python3
"""
SecurityKit fix queue (standard library only). Reads the findings in .securitykit/*report.json, re-verifies fixes,
and records them. It never edits project source code; the agent does that, with the user's approval.

  python3 fix_queue.py list   --root . [--min-severity High] [--skill sk-inject] [--all]
  python3 fix_queue.py show   --root . SK-INJ-0001
  python3 fix_queue.py verify --root . SK-INJ-0001        # re-runs the owning skill's scanner for that check
  python3 fix_queue.py mark   --root . SK-INJ-0001 --verified-by scan|test|review|dynamic --note "..."

`mark` sets "fixed": true on the finding in its report JSON and appends an entry to .securitykit/fix-log.json.
"""

import argparse
import datetime
import glob
import json
import os
import subprocess
import sys
import tempfile

from sk_outputs import prepare_output

VERSION = "0.1.0"
SEVERITIES = ["Critical", "High", "Medium", "Low"]
NEAR_LINES = 10  # a fix often shifts lines; a hit this close to the old line counts as "still there"


def reports(root):
    for path in sorted(glob.glob(os.path.join(root, ".securitykit", "*report.json"))):
        if os.path.basename(path) == "audit-report.json":
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        if (data.get("tool") or {}).get("name") == "SecurityKit" and isinstance(data.get("findings"), list):
            yield path, data


def all_findings(root):
    for path, data in reports(root):
        skill = data["tool"].get("skill", "?")
        for f in data["findings"]:
            yield path, skill, f


def find(root, fid):
    for path, skill, f in all_findings(root):
        if f.get("id") == fid:
            return path, skill, f
    raise SystemExit(f"error: finding {fid} not found in .securitykit/*report.json")


def where(f):
    loc = f.get("location") or {}
    req = f.get("request") or {}
    if loc.get("file"):
        return f"{loc['file']}:{loc.get('line', '?')}"
    return f"{req.get('method', '')} {req.get('url', '')}".strip()


def cmd_list(args):
    rows = []
    limit = SEVERITIES.index(args.min_severity)
    for path, skill, f in all_findings(args.root):
        if f.get("fixed") and not args.all:
            continue
        if SEVERITIES.index(f.get("severity", "Low")) > limit or (args.skill and skill != args.skill):
            continue
        rows.append({"id": f.get("id"), "severity": f.get("severity"), "checkId": f.get("checkId"), "skill": skill,
                     "where": where(f), "title": f.get("title"), "source": f.get("source"), "fixed": bool(f.get("fixed"))})
    rows.sort(key=lambda r: (SEVERITIES.index(r["severity"] or "Low"), r["skill"], r["id"] or ""))
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print("No open findings. Run a skill (or /sk-audit) first, or use --all to include fixed ones.")
        return 0
    print(f"{'ID':<16} {'Severity':<9} {'Check':<20} {'Where':<40} Title")
    for r in rows:
        mark = " [fixed]" if r["fixed"] else ""
        print(f"{r['id']:<16} {r['severity']:<9} {r['checkId']:<20} {r['where'][:40]:<40} {r['title']}{mark}")
    print(f"\n{len(rows)} finding(s)")
    return 0


def cmd_show(args):
    path, skill, f = find(args.root, args.id)
    print(json.dumps({"report": os.path.relpath(path, args.root).replace(os.sep, "/"), "skill": skill, "finding": f}, indent=2))
    return 0


def cmd_verify(args):
    path, skill, f = find(args.root, args.id)
    loc = f.get("location") or {}
    scanner = os.path.join(args.skills_dir, skill, "scripts", "sk_scan.py")
    result = {"id": args.id, "skill": skill, "checkId": f.get("checkId"), "source": f.get("source")}
    if not loc.get("file") or not os.path.isfile(scanner) or not os.path.isdir(os.path.join(args.skills_dir, skill, "rules")):
        result["status"] = "manual"
        result["how"] = ("re-run the probe from the finding's request" if f.get("request")
                         else "re-review the code and run the regression test; this check has no scanner rule")
        print(json.dumps(result, indent=2))
        return 0
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as fh:
        fh.write(loc["file"] + "\n")
        listing = fh.name
    try:
        r = subprocess.run([sys.executable, scanner, "--root", args.root, "--only-files", listing, "--check", f["checkId"],
                            "--include-tests", "--agent-dirs"], capture_output=True, text=True, encoding="utf-8", errors="replace")
    finally:
        os.unlink(listing)
    if r.returncode != 0:
        result.update(status="error", detail=r.stderr.strip()[:300])
        print(json.dumps(result, indent=2))
        return 1
    hits = json.loads(r.stdout).get("candidates", [])
    near = [h for h in hits if abs(h["line"] - loc.get("line", h["line"])) <= NEAR_LINES]
    if near:
        result.update(status="still-detected", hits=[{"line": h["line"], "rule": h["rule"], "snippet": h["snippet"]} for h in near])
    else:
        result["status"] = "not-detected"
        result["note"] = ("the scanner no longer flags this location" if f.get("source") == "script"
                          else "the scanner does not flag it, but this finding came from review: confirm by reading the code and running the regression test")
    if hits and not near:
        result["other_hits_in_file"] = len(hits)
    print(json.dumps(result, indent=2))
    return 0


def cmd_mark(args):
    path, skill, f = find(args.root, args.id)
    if f.get("fixed"):
        print(f"{args.id} is already marked fixed")
        return 0
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    for item in data["findings"]:
        if item.get("id") == args.id:
            item["fixed"] = True
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    log_path = os.path.join(args.root, ".securitykit", "fix-log.json")
    log = {"fixes": []}
    if os.path.exists(log_path):
        with open(log_path, encoding="utf-8") as fh:
            log = json.load(fh)
    log["fixes"].append({
        "id": args.id, "skill": skill, "checkId": f.get("checkId"), "severity": f.get("severity"), "where": where(f),
        "title": f.get("title"), "verifiedBy": args.verified_by, "note": args.note,
        "fixedAt": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
    })
    prepare_output(log_path)
    with open(log_path, "w", encoding="utf-8") as fh:
        json.dump(log, fh, indent=2)
        fh.write("\n")
    print(f"marked {args.id} fixed in {os.path.relpath(path, args.root)} (verified by {args.verified_by})")
    return 0


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="SecurityKit fix queue.")
    ap.add_argument("--version", action="version", version=VERSION)
    sub = ap.add_subparsers(dest="cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", default=".")
    common.add_argument("--skills-dir", default=os.path.join(here, "..", ".."))
    p = sub.add_parser("list", parents=[common])
    p.add_argument("--min-severity", choices=SEVERITIES, default="Low")
    p.add_argument("--skill")
    p.add_argument("--all", action="store_true", help="include findings already marked fixed")
    p.add_argument("--json", action="store_true")
    for name in ("show", "verify"):
        sub.add_parser(name, parents=[common]).add_argument("id")
    p = sub.add_parser("mark", parents=[common])
    p.add_argument("id")
    p.add_argument("--verified-by", required=True, choices=["scan", "test", "review", "dynamic"])
    p.add_argument("--note", required=True, help="what was changed (files) and how it was verified")
    args = ap.parse_args(argv)
    args.root = os.path.abspath(args.root)
    args.skills_dir = os.path.abspath(args.skills_dir)
    return {"list": cmd_list, "show": cmd_show, "verify": cmd_verify, "mark": cmd_mark}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
SecurityKit ASVS coverage map (read-only on the project, standard library only).

Maps the SecurityKit reports already in .securitykit/ onto the chapters of the OWASP Application Security
Verification Standard 5.0 and shows, per chapter: which SecurityKit skills cover it, which of those have been run,
and their open findings. It never claims compliance: a chapter is at best "no issues found by SecurityKit", and
every chapter still needs the agent's (and a human's) requirement-by-requirement review.

  python3 asvs_map.py --root . --level 2
  python3 asvs_map.py --root . --level 1 --out .securitykit/asvs-coverage.json --md security-report-asvs.md
"""

import argparse
import datetime
import glob
import json
import os
import sys

from sk_outputs import prepare_output

VERSION = "0.1.0"
SEVERITIES = ["Critical", "High", "Medium", "Low"]

# ASVS 5.0 chapters -> SecurityKit skills that test parts of them. Coverage is partial by nature.
CHAPTERS = [
    ("V1", "Encoding and Sanitization", ["sk-inject", "sk-xss", "sk-ssrf", "sk-deserialize", "sk-database"]),
    ("V2", "Validation and Business Logic", ["sk-validation", "sk-business", "sk-race", "sk-ratelimit", "sk-abuse"]),
    ("V3", "Web Frontend Security", ["sk-browser", "sk-csrf", "sk-xss", "sk-redirect", "sk-cache", "sk-nextjs"]),
    ("V4", "API and Web Service", ["sk-api", "sk-rest", "sk-graphql", "sk-openapi", "sk-websocket", "sk-grpc", "sk-webhooks", "sk-nextjs"]),
    ("V5", "File Handling", ["sk-upload"]),
    ("V6", "Authentication", ["sk-auth", "sk-password", "sk-saml", "sk-authprovider", "sk-passkeys"]),
    ("V7", "Session Management", ["sk-auth", "sk-tokens", "sk-browser", "sk-authprovider"]),
    ("V8", "Authorization", ["sk-authz", "sk-api", "sk-baas", "sk-nextjs", "sk-authprovider"]),
    ("V9", "Self-contained Tokens", ["sk-tokens"]),
    ("V10", "OAuth and OIDC", ["sk-oauth2", "sk-authprovider"]),
    ("V11", "Cryptography", ["sk-crypto", "sk-password"]),
    ("V12", "Secure Communication", ["sk-crypto", "sk-browser", "sk-grpc", "sk-paas"]),
    ("V13", "Configuration", ["sk-config", "sk-secrets", "sk-docker", "sk-cloud", "sk-cicd", "sk-paas", "sk-baas", "sk-defaults"]),
    ("V14", "Data Protection", ["sk-privacy", "sk-cache", "sk-logging", "sk-database", "sk-baas"]),
    ("V15", "Secure Coding and Architecture", ["sk-design", "sk-deps", "sk-dos", "sk-queue", "sk-defaults", "sk-ai-code"]),
    ("V16", "Security Logging and Error Handling", ["sk-logging", "sk-config"]),
    ("V17", "WebRTC", []),
]
OUTSIDE_ASVS = ["sk-ai", "sk-prompt-injection", "sk-agents", "sk-rag", "sk-mobile", "sk-electron", "sk-extension",
                "sk-domain", "sk-email", "sk-payments", "sk-tests", "sk-fuzz", "sk-repo", "sk-incident", "sk-dast",
                "sk-game", "sk-variant"]


def load_reports(root):
    out = {}
    for path in sorted(glob.glob(os.path.join(root, ".securitykit", "*report.json"))):
        if os.path.basename(path) in ("audit-report.json", "review-report.json"):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        tool = data.get("tool") or {}
        if tool.get("name") == "SecurityKit" and isinstance(data.get("findings"), list):
            out[tool.get("skill")] = {"file": os.path.relpath(path, root).replace(os.sep, "/"), "generatedAt": data.get("generatedAt"),
                                      "open": [f for f in data["findings"] if not f.get("fixed")]}
    return out


def build(root, level):
    reports = load_reports(root)
    rows = []
    for cid, title, skills in CHAPTERS:
        run = [s for s in skills if s in reports]
        open_findings = [dict(f, skill=s) for s in run for f in reports[s]["open"]]
        counts = {sev.lower(): sum(1 for f in open_findings if f.get("severity") == sev) for sev in SEVERITIES}
        if not skills:
            status = "Not covered by SecurityKit (manual review)"
        elif not run:
            status = "Not assessed (run: " + ", ".join("/" + s for s in skills) + ")"
        elif open_findings:
            status = "Issues found"
        elif len(run) < len(skills):
            status = "Partly assessed, no issues found so far"
        else:
            status = "No issues found by SecurityKit (manual review still required)"
        rows.append({"chapter": cid, "title": title, "skills": skills, "skillsRun": run, "status": status,
                     "openFindings": counts,
                     "findings": [{"id": f.get("id"), "checkId": f.get("checkId"), "severity": f.get("severity"), "title": f.get("title"), "skill": f["skill"]}
                                  for f in sorted(open_findings, key=lambda f: SEVERITIES.index(f.get("severity", "Low")))][:50]})
    return {
        "tool": "securitykit-asvs-map", "version": VERSION, "asvs": "5.0", "level": level,
        "generatedAt": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
        "reportsUsed": {k: {"file": v["file"], "generatedAt": v["generatedAt"]} for k, v in sorted(reports.items())},
        "chapters": rows,
        "outsideAsvs": [s for s in OUTSIDE_ASVS if s in reports],
        "disclaimer": "Indicative mapping of automated and agent-assisted findings to ASVS chapters. Not a verification or certification.",
    }


def render_md(r, project):
    out = [f"# ASVS {r['asvs']} Coverage (Level {r['level']})", "",
           f"**Project:** {project}  ", f"**Generated:** {r['generatedAt']} by SecurityKit sk-asvs {VERSION}  ",
           f"**Reports used:** {len(r['reportsUsed'])}", "",
           f"> {r['disclaimer']}", "",
           "## Chapters", "",
           "| Chapter | SecurityKit status | Skills run | Open C/H/M/L |", "|---|---|---|---|"]
    for c in r["chapters"]:
        o = c["openFindings"]
        out.append(f"| {c['chapter']} {c['title']} | {c['status']} | {', '.join('/' + s for s in c['skillsRun']) or '-'} | "
                   f"{o['critical']}/{o['high']}/{o['medium']}/{o['low']} |")
    out += ["", "## Open findings by chapter", ""]
    for c in r["chapters"]:
        if c["findings"]:
            out += [f"### {c['chapter']} {c['title']}", ""]
            out += [f"- **{f['severity']}** [{f['checkId']}] {f['title']} ({f['id']}, /{f['skill']})" for f in c["findings"]]
            out.append("")
    out += ["## Requirement review", "", "<!-- AGENT: per chapter, requirements reviewed manually, their result and evidence; open questions. -->", ""]
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="SecurityKit ASVS coverage map.")
    ap.add_argument("--root", default=".")
    ap.add_argument("--level", type=int, choices=[1, 2, 3], default=2)
    ap.add_argument("--out", help="default: <root>/.securitykit/asvs-coverage.json")
    ap.add_argument("--md", help="default: <root>/security-report-asvs.md")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)
    result = build(root, args.level)
    out = args.out or os.path.join(root, ".securitykit", "asvs-coverage.json")
    md = args.md or os.path.join(root, "security-report-asvs.md")
    prepare_output(out)
    prepare_output(md)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
        fh.write("\n")
    with open(md, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render_md(result, os.path.basename(root)))
    assessed = sum(1 for c in result["chapters"] if c["skillsRun"])
    print(f"{assessed}/{len(result['chapters'])} chapters touched by {len(result['reportsUsed'])} reports -> {md}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

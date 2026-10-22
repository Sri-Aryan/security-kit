#!/usr/bin/env python3
"""
SecurityKit DAST helper (standard library only). It never scans anything itself.

  python3 zap_report.py tools  --target http://localhost:3000 [--openapi openapi.yaml]
        lists the local scanners available (OWASP ZAP via Docker or a local install, nuclei) and prints the exact
        commands for a passive baseline scan or an API scan against the target, for the agent to run with consent.
  python3 zap_report.py convert --report .securitykit/zap-report.json [--out .securitykit/dast-candidates.json]
        turns a ZAP JSON report into CANDIDATES grouped by SecurityKit DAST check, for the agent to confirm.
"""

import argparse
import json
import os
import shutil
import sys
from urllib.parse import urlparse

from sk_outputs import prepare_output

VERSION = "0.1.0"
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
RISK = {0: "Info", 1: "Low", 2: "Medium", 3: "High"}
SEVERITY = {0: None, 1: "Low", 2: "Medium", 3: "High"}

# CWE -> DAST check. Unknown CWEs go to DAST-OTHER-001.
CWE_CHECK = {}
for check, cwes in {
    "DAST-INJ-001": [89, 78, 77, 90, 643, 943, 917, 94, 95, 611, 1336, 113, 74, 116],
    "DAST-XSS-001": [79, 80, 83, 87],
    "DAST-HEADERS-001": [693, 1021, 16, 1173, 345, 829],
    "DAST-COOKIE-001": [614, 1004, 1275, 565, 315],
    "DAST-INFO-001": [200, 209, 497, 550, 615, 359, 201, 540],
    "DAST-CONFIG-001": [548, 530, 538, 552, 425, 22, 23, 541],
    "DAST-TLS-001": [319, 326, 327, 311, 523, 295],
    "DAST-AUTH-001": [287, 306, 522, 525, 384, 613, 284, 285, 639],
    "DAST-CSRF-001": [352],
    "DAST-REDIR-001": [601],
    "DAST-CORS-001": [942, 264],
    "DAST-SSRF-001": [918],
}.items():
    for c in cwes:
        CWE_CHECK[c] = check


def is_local(url):
    host = (urlparse(url).hostname or "").lower()
    return host in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal") or host.endswith(".localhost")


def cmd_tools(args):
    target = args.target
    docker_target = target.replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal")
    work = os.path.abspath(".securitykit")
    tools = []
    if shutil.which("docker"):
        tools.append({"tool": "zap (docker)", "kind": "passive baseline",
                      "command": f'docker run --rm -v "{work}:/zap/wrk:rw" -t {ZAP_IMAGE} zap-baseline.py -t {docker_target} -J zap-report.json -m 2'})
        if args.openapi:
            spec = os.path.basename(args.openapi)
            tools.append({"tool": "zap (docker)", "kind": "API scan (ACTIVE: sends attack payloads)",
                          "command": f'docker run --rm -v "{work}:/zap/wrk:rw" -t {ZAP_IMAGE} zap-api-scan.py -t /zap/wrk/{spec} -f openapi -J zap-report.json',
                          "note": f"copy {args.openapi} into .securitykit/ first; run only against a disposable environment"})
    for exe in ("zap-baseline.py", "zap.sh", "zap.bat"):
        if shutil.which(exe):
            tools.append({"tool": exe, "kind": "local ZAP install", "command": f"{exe} -t {target} -J .securitykit/zap-report.json" if exe.startswith("zap-baseline") else f"{exe} -cmd -quickurl {target} -quickout .securitykit/zap-report.json"})
    if shutil.which("nuclei"):
        tools.append({"tool": "nuclei", "kind": "template scan (some templates are intrusive)",
                      "command": f"nuclei -u {target} -severity medium,high,critical -exclude-tags dos,intrusive,fuzz -jsonl -o .securitykit/nuclei.jsonl"})
    result = {"tool": "securitykit-dast-tools", "version": VERSION, "target": target, "target_is_local": is_local(target),
              "available": tools,
              "notes": ["Baseline scans are passive (spider + passive rules) and safe for test environments you own.",
                        "Active/API scans send attack payloads: only against disposable environments with explicit consent.",
                        "Non-local targets require the user's confirmation that they own the host."]}
    if not tools:
        result["install_hint"] = "Install Docker (then the ZAP image is pulled on first run) or OWASP ZAP from zaproxy.org."
    print(json.dumps(result, indent=2))
    return 0


def cmd_convert(args):
    with open(args.report, encoding="utf-8") as fh:
        data = json.load(fh)
    sites = data.get("site") or []
    if isinstance(sites, dict):
        sites = [sites]
    candidates = []
    for site in sites:
        for a in site.get("alerts") or []:
            risk = int(str(a.get("riskcode", "0")) or 0)
            if risk == 0 and not args.include_info:
                continue
            try:
                cwe = int(str(a.get("cweid", "-1")))
            except ValueError:
                cwe = -1
            instances = a.get("instances") or []
            candidates.append({
                "check": CWE_CHECK.get(cwe, "DAST-OTHER-001"), "severity": SEVERITY.get(risk) or "Low", "zapRisk": RISK.get(risk),
                "confidence": a.get("confidence"), "alert": a.get("alert") or a.get("name"), "pluginId": a.get("pluginid"),
                "cwe": f"CWE-{cwe}" if cwe > 0 else None, "site": site.get("@name"),
                "count": int(str(a.get("count", len(instances))) or 0),
                "instances": [{"method": i.get("method"), "uri": i.get("uri"), "param": i.get("param"),
                               "evidence": (i.get("evidence") or "")[:200]} for i in instances[:5]],
                "solution": (a.get("solution") or "").replace("<p>", "").replace("</p>", " ").strip()[:400],
            })
    candidates.sort(key=lambda c: (["High", "Medium", "Low"].index(c["severity"]) if c["severity"] in ("High", "Medium", "Low") else 3, c["check"]))
    result = {"tool": "securitykit-dast-convert", "version": VERSION, "source": args.report,
              "summary": {k: sum(1 for c in candidates if c["check"] == k) for k in sorted({c["check"] for c in candidates})},
              "candidates": candidates}
    text = json.dumps(result, indent=2)
    if args.out:
        prepare_output(args.out)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"{len(candidates)} alert(s) -> {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="SecurityKit DAST helper.")
    ap.add_argument("--version", action="version", version=VERSION)
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("tools")
    t.add_argument("--target", required=True)
    t.add_argument("--openapi")
    c = sub.add_parser("convert")
    c.add_argument("--report", required=True)
    c.add_argument("--out")
    c.add_argument("--include-info", action="store_true")
    args = ap.parse_args(argv)
    return cmd_tools(args) if args.cmd == "tools" else cmd_convert(args)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
SecurityKit compliance map (read-only on the project, standard library only).

Maps open findings from the SecurityKit reports in .securitykit/ to controls of common frameworks, so engineering work
can be tied to audit evidence: SOC 2 (Trust Services Criteria 2017, rev. 2022), ISO/IEC 27001:2022 Annex A,
PCI DSS v4.0, HIPAA Security Rule (45 CFR 164.308/312) and GDPR. The mapping is indicative and at skill level: a finding
from /sk-authz relates to access-control controls, and so on. It is not an audit opinion.

  python3 compliance_map.py --root . --framework soc2,iso27001
  python3 compliance_map.py --root . --framework all --md security-report-compliance.md
"""

import argparse
import datetime
import glob
import json
import os
import sys

VERSION = "0.1.0"
SEVERITIES = ["Critical", "High", "Medium", "Low"]

FRAMEWORKS = {
    "soc2": "SOC 2 (Trust Services Criteria)",
    "iso27001": "ISO/IEC 27001:2022 Annex A",
    "pci": "PCI DSS v4.0",
    "hipaa": "HIPAA Security Rule",
    "gdpr": "GDPR",
}

# Control labels, kept short. Control IDs are the frameworks' own.
CONTROLS = {
    "soc2": {
        "CC6.1": "Logical access security software, infrastructure and architectures",
        "CC6.2": "User registration and authorization",
        "CC6.3": "Role-based access, least privilege, removal of access",
        "CC6.6": "Protection against threats from outside system boundaries",
        "CC6.7": "Restriction and protection of data in transmission and movement",
        "CC6.8": "Prevention/detection of unauthorized or malicious software",
        "CC7.1": "Detection of configuration changes and vulnerabilities",
        "CC7.2": "Monitoring of system components for anomalies",
        "CC7.3": "Evaluation of security events",
        "CC7.4": "Incident response",
        "CC8.1": "Change management",
        "CC9.2": "Vendor and business partner risk",
        "C1.1": "Identification and protection of confidential information",
        "P4.1": "Use, retention and disposal of personal information",
    },
    "iso27001": {
        "5.15": "Access control", "5.17": "Authentication information", "5.18": "Access rights",
        "5.23": "Information security for use of cloud services", "5.24": "Incident management planning",
        "5.26": "Response to information security incidents", "5.34": "Privacy and protection of PII",
        "8.2": "Privileged access rights", "8.3": "Information access restriction", "8.4": "Access to source code",
        "8.5": "Secure authentication", "8.7": "Protection against malware",
        "8.8": "Management of technical vulnerabilities", "8.9": "Configuration management",
        "8.10": "Information deletion", "8.11": "Data masking", "8.12": "Data leakage prevention",
        "8.15": "Logging", "8.16": "Monitoring activities", "8.20": "Networks security",
        "8.24": "Use of cryptography", "8.25": "Secure development life cycle",
        "8.26": "Application security requirements", "8.28": "Secure coding", "8.29": "Security testing in development and acceptance",
        "8.31": "Separation of development, test and production environments", "8.32": "Change management",
    },
    "pci": {
        "Req 2": "Apply secure configurations to all system components",
        "Req 3": "Protect stored account data",
        "Req 4": "Protect cardholder data with strong cryptography during transmission",
        "Req 6": "Develop and maintain secure systems and software (incl. 6.2.4 common software attacks, 6.3.3 patching, 6.4 public-facing web apps)",
        "Req 7": "Restrict access by business need to know",
        "Req 8": "Identify users and authenticate access",
        "Req 10": "Log and monitor all access",
        "Req 11": "Test security of systems and networks regularly",
        "Req 12": "Support information security with organizational policies (incl. 12.10 incident response)",
    },
    "hipaa": {
        "164.308(a)(1)": "Security management process (risk analysis and management)",
        "164.308(a)(5)": "Security awareness and training (incl. malicious software, log-in monitoring, password management)",
        "164.308(a)(6)": "Security incident procedures",
        "164.308(a)(7)": "Contingency plan (backups, disaster recovery)",
        "164.312(a)(1)": "Access control (unique user ID, automatic logoff, encryption)",
        "164.312(b)": "Audit controls",
        "164.312(c)(1)": "Integrity",
        "164.312(d)": "Person or entity authentication",
        "164.312(e)(1)": "Transmission security",
    },
    "gdpr": {
        "Art. 5": "Principles (minimization, storage limitation, integrity and confidentiality)",
        "Art. 17": "Right to erasure",
        "Art. 20": "Right to data portability",
        "Art. 25": "Data protection by design and by default",
        "Art. 28": "Processors",
        "Art. 30": "Records of processing activities",
        "Art. 32": "Security of processing",
        "Art. 33": "Notification of a personal data breach",
    },
}

# Skill -> related controls per framework.
ACCESS = {"soc2": ["CC6.1", "CC6.3"], "iso27001": ["5.15", "8.3", "8.2"], "pci": ["Req 7"], "hipaa": ["164.312(a)(1)"], "gdpr": ["Art. 32"]}
AUTHN = {"soc2": ["CC6.1", "CC6.2"], "iso27001": ["5.17", "8.5"], "pci": ["Req 8"], "hipaa": ["164.312(d)"], "gdpr": ["Art. 32"]}
APPSEC = {"soc2": ["CC6.6", "CC7.1"], "iso27001": ["8.26", "8.28"], "pci": ["Req 6"], "hipaa": ["164.312(c)(1)"], "gdpr": ["Art. 32"]}
CRYPTO = {"soc2": ["CC6.1", "CC6.7"], "iso27001": ["8.24"], "pci": ["Req 3", "Req 4"], "hipaa": ["164.312(a)(1)", "164.312(e)(1)"], "gdpr": ["Art. 32"]}
CONFIG = {"soc2": ["CC7.1", "CC6.6"], "iso27001": ["8.9", "8.20"], "pci": ["Req 2"], "hipaa": ["164.308(a)(1)"], "gdpr": ["Art. 32"]}
LOGS = {"soc2": ["CC7.2", "CC7.3"], "iso27001": ["8.15", "8.16"], "pci": ["Req 10"], "hipaa": ["164.312(b)"], "gdpr": ["Art. 32", "Art. 33"]}
PRIVACY = {"soc2": ["C1.1", "P4.1"], "iso27001": ["5.34", "8.10", "8.11", "8.12"], "pci": ["Req 3"], "hipaa": ["164.312(a)(1)"], "gdpr": ["Art. 5", "Art. 17", "Art. 20", "Art. 25", "Art. 30"]}
VULN = {"soc2": ["CC7.1", "CC9.2"], "iso27001": ["8.8", "8.25"], "pci": ["Req 6"], "hipaa": ["164.308(a)(1)"], "gdpr": ["Art. 32"]}
SDLC = {"soc2": ["CC8.1"], "iso27001": ["8.25", "8.29", "8.32", "8.4"], "pci": ["Req 6", "Req 11"], "hipaa": ["164.308(a)(1)"], "gdpr": ["Art. 25"]}
IR = {"soc2": ["CC7.3", "CC7.4"], "iso27001": ["5.24", "5.26"], "pci": ["Req 12"], "hipaa": ["164.308(a)(6)", "164.308(a)(7)"], "gdpr": ["Art. 33"]}


def merge(*maps):
    out = {}
    for m in maps:
        for fw, ids in m.items():
            out.setdefault(fw, [])
            out[fw] += [i for i in ids if i not in out[fw]]
    return out


SKILL_MAP = {
    "sk-api": merge(ACCESS, APPSEC), "sk-rest": APPSEC, "sk-graphql": merge(ACCESS, APPSEC), "sk-openapi": APPSEC,
    "sk-webhooks": merge(APPSEC, CRYPTO), "sk-auth": AUTHN, "sk-password": merge(AUTHN, CRYPTO), "sk-tokens": merge(AUTHN, CRYPTO),
    "sk-oauth2": AUTHN, "sk-saml": AUTHN, "sk-authz": ACCESS, "sk-inject": APPSEC, "sk-xss": APPSEC, "sk-ssrf": APPSEC,
    "sk-redirect": APPSEC, "sk-deserialize": APPSEC, "sk-upload": merge(APPSEC, {"soc2": ["CC6.8"], "iso27001": ["8.7"]}),
    "sk-database": merge(ACCESS, APPSEC, CRYPTO), "sk-business": APPSEC, "sk-race": APPSEC,
    "sk-payments": merge(APPSEC, {"pci": ["Req 3", "Req 4", "Req 6"]}), "sk-ratelimit": APPSEC, "sk-email": APPSEC,
    "sk-ai": merge(APPSEC, PRIVACY), "sk-prompt-injection": APPSEC, "sk-agents": merge(ACCESS, APPSEC), "sk-rag": merge(ACCESS, PRIVACY),
    "sk-secrets": merge(AUTHN, CRYPTO, CONFIG), "sk-docker": CONFIG, "sk-cicd": merge(SDLC, CONFIG), "sk-cloud": merge(CONFIG, ACCESS, CRYPTO, {"soc2": ["CC6.6"], "iso27001": ["5.23"]}),
    "sk-design": SDLC, "sk-tests": SDLC, "sk-fuzz": SDLC, "sk-deps": VULN, "sk-crypto": CRYPTO, "sk-logging": LOGS,
    "sk-privacy": PRIVACY, "sk-config": CONFIG, "sk-csrf": APPSEC, "sk-browser": merge(APPSEC, CONFIG), "sk-dos": APPSEC,
    "sk-validation": APPSEC, "sk-mobile": merge(APPSEC, CRYPTO), "sk-electron": APPSEC, "sk-websocket": merge(ACCESS, APPSEC),
    "sk-queue": merge(APPSEC, CONFIG), "sk-cache": merge(APPSEC, PRIVACY), "sk-grpc": merge(ACCESS, APPSEC, CRYPTO),
    "sk-domain": merge(CONFIG, {"soc2": ["CC6.6"]}), "sk-extension": APPSEC, "sk-dast": merge(APPSEC, {"pci": ["Req 11"], "iso27001": ["8.29"]}),
    "sk-repo": SDLC, "sk-incident": IR,
}


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
            out[tool.get("skill")] = [f for f in data["findings"] if not f.get("fixed")]
    return out


def build(root, frameworks):
    reports = load_reports(root)
    result = {"tool": "securitykit-compliance-map", "version": VERSION,
              "generatedAt": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
              "skillsRun": sorted(reports), "frameworks": {},
              "disclaimer": "Indicative mapping of security findings to framework controls. Not an audit opinion or certification."}
    for fw in frameworks:
        controls = {}
        for cid, label in CONTROLS[fw].items():
            skills = sorted(s for s, m in SKILL_MAP.items() if cid in m.get(fw, []))
            run = [s for s in skills if s in reports]
            findings = [{"id": f.get("id"), "checkId": f.get("checkId"), "severity": f.get("severity"), "title": f.get("title"), "skill": s}
                        for s in run for f in reports[s]]
            findings.sort(key=lambda f: SEVERITIES.index(f.get("severity") or "Low"))
            if not skills:
                status = "Process/organizational control: provide evidence manually"
            elif not run:
                status = "No technical evidence yet (run: " + ", ".join("/" + s for s in skills[:6]) + ")"
            elif findings:
                status = f"{len(findings)} open finding(s)"
            else:
                status = "No open SecurityKit findings in related skills"
            controls[cid] = {"label": label, "relatedSkills": skills, "skillsRun": run, "status": status, "findings": findings[:50]}
        result["frameworks"][fw] = {"name": FRAMEWORKS[fw], "controls": controls}
    return result


def render_md(r, project):
    out = ["# Compliance Mapping", "", f"**Project:** {project}  ", f"**Generated:** {r['generatedAt']} by SecurityKit sk-compliance {VERSION}  ",
           f"**SecurityKit reports used:** {', '.join('/' + s for s in r['skillsRun']) or 'none'}", "", f"> {r['disclaimer']}", ""]
    for fw in r["frameworks"].values():
        out += [f"## {fw['name']}", "", "| Control | Status | Open findings (top) |", "|---|---|---|"]
        for cid, c in fw["controls"].items():
            top = "; ".join(f"{f['severity']} {f['checkId']} ({f['id']})" for f in c["findings"][:3])
            out.append(f"| **{cid}** {c['label']} | {c['status']} | {top or '-'} |")
        out.append("")
    out += ["## Evidence and gaps", "", "<!-- AGENT: per framework, what evidence exists, what is missing, and which process controls the user must document. -->", ""]
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="SecurityKit compliance map.")
    ap.add_argument("--root", default=".")
    ap.add_argument("--framework", default="all", help="comma list of: " + ", ".join(FRAMEWORKS) + " (or all)")
    ap.add_argument("--out", help="default: <root>/.securitykit/compliance-map.json")
    ap.add_argument("--md", help="default: <root>/security-report-compliance.md")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)
    wanted = list(FRAMEWORKS) if args.framework == "all" else [f.strip() for f in args.framework.split(",") if f.strip()]
    bad = [f for f in wanted if f not in FRAMEWORKS]
    if bad:
        print(f"error: unknown framework(s): {', '.join(bad)} (choose from {', '.join(FRAMEWORKS)})", file=sys.stderr)
        return 2
    root = os.path.abspath(args.root)
    result = build(root, wanted)
    out = args.out or os.path.join(root, ".securitykit", "compliance-map.json")
    md = args.md or os.path.join(root, "security-report-compliance.md")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
        fh.write("\n")
    with open(md, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render_md(result, os.path.basename(root)))
    print(f"{len(wanted)} framework(s), {len(result['skillsRun'])} reports -> {md}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
SecurityKit incident-readiness inventory (read-only, standard library only).

Collects evidence of incident readiness that a repository can show: incident/runbook documents, a security contact,
alerting and paging integrations, backup and restore configuration, key/secret rotation tooling, audit logging,
and session/token revocation code. Everything it can't see (who is on call, whether backups were ever restored) is
for the agent to ask.

  python3 ir_inventory.py --root . --out .securitykit/ir-inventory.json
"""

import argparse
import json
import os
import re
import sys

from sk_outputs import prepare_output

VERSION = "0.1.0"
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "target", ".next", "__pycache__", ".venv", "venv",
             ".securitykit", ".claude", ".codex", ".agents", "coverage", ".terraform", "bin", "obj"}
TEXT_EXT = {".md", ".txt", ".rst", ".adoc", ".yml", ".yaml", ".json", ".toml", ".tf", ".js", ".ts", ".py", ".go",
            ".rb", ".java", ".kt", ".cs", ".php", ".sh", ".conf", ".ini", ".hcl"}

SIGNALS = {
    "IR-PLAN-001": ("incident response plan / runbooks", r"(?i)(incident[ _-]?response|incident[ _-]?runbook|security[ _-]?incident|playbook|runbook|post[ _-]?mortem|breach[ _-]?(notification|response))", "doc"),
    "IR-CONTACT-001": ("security contact", r"(?i)(security@|^Contact:\s*mailto:|vulnerability disclosure|report a vulnerability)", "doc"),
    "IR-ALERT-001": ("alerting / paging", r"(?i)(pagerduty|opsgenie|victorops|splunk on-call|incident\.io|firehydrant|rootly|alertmanager|PrometheusRule|aws_cloudwatch_metric_alarm|azurerm_monitor_metric_alert|google_monitoring_alert_policy|datadog_monitor|grafana.*alert|sentry.*alert|statuspage)", "any"),
    "IR-BACKUP-001": ("backups / restore", r"(?i)(aws_backup_plan|backup_retention_period|point_in_time_recovery|pitr|velero|restic|borg|pgbackrest|wal-g|barman|mongodump|pg_dump|mysqldump|snapshot_?schedule|azurerm_backup|google_sql_database_instance[^\n]*backup|restore[ _-]?(test|drill|procedure))", "any"),
    "IR-ROTATE-001": ("secret / key rotation", r"(?i)(rotate[ _-]?(secret|key|token|credential)s?|rotation[ _-]?(schedule|lambda|policy)|aws_secretsmanager_secret_rotation|enable_key_rotation|key[ _-]?rotation|vault.*(rotate|lease))", "any"),
    "IR-AUDIT-001": ("audit / security event logging", r"(?i)(audit[_ ]?log|auditLog|audit_trail|authn_login_fail|login_failed|authz_fail|cloudtrail|aws_cloudtrail|activity[ _-]?log|security[_ ]?event)", "any"),
    "IR-REVOKE-001": ("session / token revocation", r"(?i)(revoke\w*\(|invalidate_?all_?sessions|logout_?all|logoutAll|sign_?out_?everywhere|token_?version|session_?version|deny_?list|blocklist|jti)", "code"),
}


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not (d.startswith(".") and d not in (".github", ".gitlab", ".well-known")))
        for f in sorted(filenames):
            if os.path.splitext(f)[1].lower() in TEXT_EXT or f in ("SECURITY", "Jenkinsfile"):
                yield os.path.relpath(os.path.join(dirpath, f), root).replace(os.sep, "/")


def main(argv=None):
    ap = argparse.ArgumentParser(description="SecurityKit incident-readiness inventory.")
    ap.add_argument("--root", default=".")
    ap.add_argument("--out")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)
    found = {k: [] for k in SIGNALS}
    for rel in walk(root):
        is_doc = rel.lower().endswith((".md", ".txt", ".rst", ".adoc")) or "/docs/" in "/" + rel.lower()
        try:
            with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as fh:
                text = fh.read(400_000)
        except OSError:
            continue
        for check, (_, rx, where) in SIGNALS.items():
            if where == "doc" and not is_doc:
                continue
            if where == "code" and is_doc:
                continue
            m = re.search(rx, text, re.M)
            if m and len(found[check]) < 10:
                found[check].append({"file": rel, "line": text.count("\n", 0, m.start()) + 1, "match": m.group(0)[:60]})
    result = {
        "tool": "securitykit-ir-inventory", "version": VERSION,
        "evidence": {k: {"area": SIGNALS[k][0], "found": v} for k, v in found.items()},
        "missing": [f"{k}: {SIGNALS[k][0]}" for k, v in found.items() if not v],
        "ask_user": [
            "Who is on call for security incidents, and how are they reached out of hours?",
            "Is there a written incident response plan, and when was it last exercised (tabletop or drill)?",
            "Which regulators, customers or partners must be notified of a breach, and within what deadline?",
            "When were backups last restored successfully, and what are the RPO/RTO targets?",
            "Can you revoke all sessions/tokens and rotate all secrets quickly? How long would it take?",
            "Where are logs kept, for how long, and who can access them during an investigation?",
        ],
    }
    text = json.dumps(result, indent=2)
    if args.out:
        prepare_output(args.out)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"{len(SIGNALS) - len(result['missing'])}/{len(SIGNALS)} areas with evidence -> {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

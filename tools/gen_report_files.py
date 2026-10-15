#!/usr/bin/env python3
"""
Generate templates/report.md and schema/report.schema.json for the concept skills.

The report shape is shared; only the title, ID prefix and inventory table differ per skill.
Run after adding a skill here:  python tools/gen_report_files.py
"""
import json
import os
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SKILLS = {
    "sk-graphql": {
        "prefix": "GQL", "title": "GraphQL Security Report", "report": "security-report-graphql.md",
        "inventory_title": "GraphQL surface",
        "inventory_intro": "{{endpoint_count}} endpoint(s), {{query_count}} queries, {{mutation_count}} mutations, {{subscription_count}} subscriptions. Introspection: {{introspection_status}}.",
        "inventory_cols": ["Kind", "Name", "Defined at", "Auth / guards", "Findings"],
        "inventory_row": ["{{kind}}", "`{{name}}`", "`{{file}}:{{line}}`", "{{guards}}", "{{finding_ids}}"],
    },
    "sk-webhooks": {
        "prefix": "WH", "title": "Webhook Security Report", "report": "security-report-webhooks.md",
        "inventory_title": "Webhook inventory",
        "inventory_intro": "{{receiver_count}} inbound receiver(s), {{sender_count}} outbound sender(s).",
        "inventory_cols": ["Direction", "Endpoint / sender", "Defined at", "Verification", "Findings"],
        "inventory_row": ["{{direction}}", "`{{name}}`", "`{{file}}:{{line}}`", "{{verification}}", "{{finding_ids}}"],
    },
    "sk-openapi": {
        "prefix": "OAS", "title": "OpenAPI Contract Report", "report": "security-report-openapi.md",
        "inventory_title": "Spec vs code",
        "inventory_intro": "Spec: `{{spec_file}}` ({{spec_version}}), {{spec_ops}} operations. Code: {{code_routes}} routes. Undocumented: {{undocumented}} · Stale: {{stale}} · Auth mismatches: {{auth_mismatch}}.",
        "inventory_cols": ["Method", "Path", "In spec", "In code", "Spec security", "Code auth", "Findings"],
        "inventory_row": ["{{method}}", "`{{path}}`", "{{in_spec}}", "{{in_code}}", "{{spec_security}}", "{{code_auth}}", "{{finding_ids}}"],
    },
    "sk-auth": {
        "prefix": "AUTH", "title": "Authentication Security Report", "report": "security-report-auth.md",
        "inventory_title": "Authentication flows",
        "inventory_intro": "Mechanisms: {{mechanisms}}. Password hashing: {{hashing}}. MFA: {{mfa}}. Session: {{session_type}}.",
        "inventory_cols": ["Flow", "Entry point", "Defined at", "Controls found", "Findings"],
        "inventory_row": ["{{flow}}", "`{{entry}}`", "`{{file}}:{{line}}`", "{{controls}}", "{{finding_ids}}"],
    },
    "sk-tokens": {
        "prefix": "TOK", "title": "Token Security Report", "report": "security-report-tokens.md",
        "inventory_title": "Token inventory",
        "inventory_intro": "{{token_kinds}} kind(s) of token found.",
        "inventory_cols": ["Token", "Issued at", "Verified at", "Lifetime", "Stored in", "Findings"],
        "inventory_row": ["{{token}}", "`{{issue_site}}`", "`{{verify_site}}`", "{{lifetime}}", "{{storage}}", "{{finding_ids}}"],
    },
    "sk-secrets": {
        "prefix": "SEC", "title": "Secrets Exposure Report", "report": "security-report-secrets.md",
        "inventory_title": "Secrets found",
        "inventory_intro": "{{secret_count}} secret(s) in the working tree, {{history_count}} only in git history. Rotation required: {{rotate_count}}.",
        "inventory_cols": ["Type", "Location", "Committed", "In history only", "Rotate", "Findings"],
        "inventory_row": ["{{type}}", "`{{file}}:{{line}}`", "{{tracked}}", "{{history_only}}", "{{rotate}}", "{{finding_ids}}"],
    },
    "sk-deps": {
        "prefix": "DEP", "title": "Dependency Security Report", "report": "security-report-deps.md",
        "inventory_title": "Dependency inventory",
        "inventory_intro": "{{ecosystems}}: {{package_count}} packages ({{direct_count}} direct). Vulnerability lookup: {{vuln_source}}.",
        "inventory_cols": ["Ecosystem", "Package", "Version", "Direct", "Advisories", "Fixed in", "Findings"],
        "inventory_row": ["{{ecosystem}}", "`{{name}}`", "{{version}}", "{{direct}}", "{{advisories}}", "{{fixed}}", "{{finding_ids}}"],
    },
    "sk-config": {
        "prefix": "CFG", "title": "Configuration Security Report", "report": "security-report-config.md",
        "inventory_title": "Configuration sources",
        "inventory_intro": "Environments seen: {{environments}}. Deployment artifacts: {{artifacts}}.",
        "inventory_cols": ["Source", "Kind", "Environment", "Findings"],
        "inventory_row": ["`{{file}}`", "{{kind}}", "{{environment}}", "{{finding_ids}}"],
    },
    "sk-inject": {
        "prefix": "INJ", "title": "Injection Security Report", "report": "security-report-inject.md",
        "inventory_title": "Sinks reviewed",
        "inventory_intro": "{{sink_count}} sink(s) reviewed across {{classes}} injection class(es).",
        "inventory_cols": ["Class", "Sink", "Location", "Input source", "Verdict", "Findings"],
        "inventory_row": ["{{class}}", "`{{sink}}`", "`{{file}}:{{line}}`", "{{source}}", "{{verdict}}", "{{finding_ids}}"],
    },
    "sk-database": {
        "prefix": "DB", "title": "Database Security Report", "report": "security-report-database.md",
        "inventory_title": "Data stores",
        "inventory_intro": "Stores: {{stores}}. Access layer: {{orm}}. Raw query sites: {{raw_count}}.",
        "inventory_cols": ["Store", "Connection defined at", "TLS", "DB user", "Exposure", "Findings"],
        "inventory_row": ["{{store}}", "`{{file}}:{{line}}`", "{{tls}}", "{{db_user}}", "{{exposure}}", "{{finding_ids}}"],
    },
}

TEMPLATE = """<!--
SecurityKit report template. Fill every {{{{placeholder}}}}; keep headings and their order.
Repeat the FINDING block once per confirmed finding, sorted by severity then check ID.
If a severity group has no findings, write "None." under its heading.
Never include secrets: redact to the first 4 characters + "…".
-->
# {title}

**Project:** {{{{project_name}}}}
**Generated:** {{{{generated_at}}}} by SecurityKit {skill} {{{{skill_version}}}}
**Scope:** {{{{scope}}}}  <!-- "full checklist" or "section: <name>" -->
**Modes:** static {{{{static_mode}}}} · dynamic {{{{dynamic_status}}}}

## Score: {{{{score}}}}/100

| Critical | High | Medium | Low | Passed | Skipped | Needs review |
|---:|---:|---:|---:|---:|---:|---:|
| {{{{critical}}}} | {{{{high}}}} | {{{{medium}}}} | {{{{low}}}} | {{{{passed_count}}}} | {{{{skipped_count}}}} | {{{{review_count}}}} |

Score = 100 − 25×Critical − 10×High − 4×Medium − 1×Low (minimum 0).
{{{{candidates_reviewed}}}} candidates reviewed, {{{{candidates_rejected}}}} rejected as false positives.

### Top fixes

1. {{{{top_fix_1}}}}
2. {{{{top_fix_2}}}}
3. {{{{top_fix_3}}}}

---

## Findings

### Critical

<!-- FINDING -->
#### [{{{{check_id}}}}] {{{{title}}}}

| | |
|---|---|
| **Severity** | {{{{severity}}}} |
| **Location** | `{{{{file}}}}:{{{{line}}}}`  <!-- or: `{{{{method}}}} {{{{url}}}}` → {{{{status}}}} --> |
| **References** | OWASP {{{{owasp}}}} · {{{{cwe}}}} |

**Evidence**

```{{{{lang}}}}
{{{{evidence_snippet}}}}
```

**Impact.** {{{{impact}}}}

**Fix.** {{{{fix}}}}

**Regression test.** {{{{regression_test}}}}
<!-- /FINDING -->

### High

### Medium

### Low

---

## Needs manual review

<!-- Plausible issues that could not be proven with evidence. Not counted in the score. -->

| Check | Where | Why it could not be confirmed |
|---|---|---|
| {{{{check_id}}}} | {{{{location}}}} | {{{{reason}}}} |

## Checks passed

| Check | Title | Note |
|---|---|---|
| {{{{check_id}}}} | {{{{title}}}} | {{{{note}}}} |

## Checks skipped

| Check | Title | Reason |
|---|---|---|
| {{{{check_id}}}} | {{{{title}}}} | {{{{reason}}}} <!-- e.g. "dynamic, no endpoint URL", "not applicable: <why>" --> |

## {inventory_title}

{inventory_intro}

| {cols} |
|{seps}|
| {row} |

---

*A clean report is not a guarantee of security. SecurityKit finds common, checkable issues;
it does not replace a professional penetration test or threat model. All analysis ran locally;
no code left this machine.*
"""


def schema(skill, prefix):
    check = {"type": "string", "pattern": f"^{prefix}-[A-Z]+-[0-9]{{3}}$"}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://github.com/getsecuritykit/kit/skills/{skill}/schema/report.schema.json",
        "title": f"SecurityKit {skill} report",
        "type": "object",
        "required": ["schemaVersion", "tool", "generatedAt", "scope", "modes", "score", "summary",
                     "findings", "passed", "skipped", "inventory"],
        "additionalProperties": False,
        "properties": {
            "schemaVersion": {"const": "1.0"},
            "tool": {
                "type": "object", "required": ["name", "skill", "version"], "additionalProperties": False,
                "properties": {"name": {"const": "SecurityKit"}, "skill": {"const": skill}, "version": {"type": "string"}},
            },
            "generatedAt": {"type": "string", "format": "date-time"},
            "project": {"type": "object", "additionalProperties": False, "properties": {"name": {"type": "string"}}},
            "scope": {
                "type": "object", "required": ["type"], "additionalProperties": False,
                "properties": {"type": {"enum": ["full", "section"]}, "section": {"type": "string"}},
            },
            "modes": {
                "type": "object", "required": ["static", "dynamic"], "additionalProperties": False,
                "properties": {
                    "static": {"type": "boolean"},
                    "dynamic": {"type": "boolean"},
                    "target": {"type": ["string", "null"], "description": "URL probed in dynamic mode"},
                    "ownershipConfirmed": {"type": "boolean"},
                    "fix": {"type": "boolean"},
                    "tests": {"type": "boolean"},
                },
            },
            "score": {"type": "integer", "minimum": 0, "maximum": 100},
            "summary": {
                "type": "object", "required": ["critical", "high", "medium", "low", "passed", "skipped"],
                "additionalProperties": False,
                "properties": {k: {"type": "integer", "minimum": 0} for k in [
                    "critical", "high", "medium", "low", "passed", "skipped", "needsReview",
                    "candidatesReviewed", "candidatesRejected"]},
            },
            "findings": {"type": "array", "items": {"$ref": "#/$defs/finding"}},
            "needsReview": {
                "type": "array",
                "items": {"type": "object", "required": ["checkId", "location", "reason"], "additionalProperties": False,
                          "properties": {"checkId": {"$ref": "#/$defs/checkId"}, "location": {"type": "string"},
                                         "reason": {"type": "string"}}},
            },
            "passed": {
                "type": "array",
                "items": {"type": "object", "required": ["checkId"], "additionalProperties": False,
                          "properties": {"checkId": {"$ref": "#/$defs/checkId"}, "title": {"type": "string"},
                                         "note": {"type": "string"}}},
            },
            "skipped": {
                "type": "array",
                "items": {"type": "object", "required": ["checkId", "reason"], "additionalProperties": False,
                          "properties": {"checkId": {"$ref": "#/$defs/checkId"}, "title": {"type": "string"},
                                         "reason": {"type": "string", "minLength": 1}}},
            },
            "inventory": {
                "type": "array",
                "description": "What was audited (operations, receivers/senders, spec-vs-code rows). Shape varies by skill.",
                "items": {"type": "object", "required": ["kind", "name"],
                          "properties": {"kind": {"type": "string"}, "name": {"type": "string"},
                                         "file": {"type": "string"}, "line": {"type": "integer", "minimum": 1},
                                         "findingIds": {"type": "array", "items": {"type": "string"}}}},
            },
        },
        "$defs": {
            "checkId": check,
            "severity": {"enum": ["Critical", "High", "Medium", "Low"]},
            "location": {
                "type": "object", "required": ["file", "line"], "additionalProperties": False,
                "properties": {"file": {"type": "string", "description": "Path relative to the project root, forward slashes"},
                               "line": {"type": "integer", "minimum": 1}, "endLine": {"type": "integer", "minimum": 1}},
            },
            "request": {
                "type": "object", "required": ["method", "url", "status", "responseExcerpt"], "additionalProperties": False,
                "properties": {"method": {"type": "string"}, "url": {"type": "string"}, "as": {"type": "string"},
                               "requestExcerpt": {"type": "string"}, "status": {"type": "integer"},
                               "responseExcerpt": {"type": "string"}},
            },
            "finding": {
                "type": "object",
                "required": ["id", "checkId", "title", "severity", "evidence", "impact", "fix", "regressionTest",
                             "references", "source"],
                "additionalProperties": False,
                "anyOf": [{"required": ["location"]}, {"required": ["request"]}],
                "properties": {
                    "id": {"type": "string", "pattern": f"^SK-{prefix}-[0-9]{{4}}$"},
                    "checkId": {"$ref": "#/$defs/checkId"},
                    "title": {"type": "string", "minLength": 1},
                    "severity": {"$ref": "#/$defs/severity"},
                    "location": {"$ref": "#/$defs/location"},
                    "request": {"$ref": "#/$defs/request"},
                    "evidence": {"type": "string", "minLength": 1},
                    "impact": {"type": "string", "minLength": 1},
                    "fix": {"type": "string", "minLength": 1},
                    "regressionTest": {"type": "string", "minLength": 1},
                    "references": {
                        "type": "object", "required": ["owasp", "cwe"], "additionalProperties": False,
                        "properties": {
                            "owasp": {"type": "array", "description": "OWASP API Top 10 2023 (API1-API10) or OWASP Top 10 2021 (A01-A10)",
                                      "items": {"type": "string", "pattern": "^(API([1-9]|10)(:2023)?|A(0[1-9]|10)(:2021)?)$"}},
                            "cwe": {"type": "array", "items": {"type": "string", "pattern": "^CWE-[0-9]+$"}},
                        },
                    },
                    "source": {"enum": ["script", "review", "dynamic"]},
                    "severityAdjusted": {"type": "string"},
                    "fixed": {"type": "boolean"},
                },
            },
        },
    }


for skill, cfg in SKILLS.items():
    base = os.path.join(ROOT, "skills", skill)
    os.makedirs(os.path.join(base, "templates"), exist_ok=True)
    os.makedirs(os.path.join(base, "schema"), exist_ok=True)
    md = TEMPLATE.format(
        title=cfg["title"], skill=skill, inventory_title=cfg["inventory_title"],
        inventory_intro=cfg["inventory_intro"],
        cols=" | ".join(cfg["inventory_cols"]), seps="|".join("---" for _ in cfg["inventory_cols"]),
        row=" | ".join(cfg["inventory_row"]),
    )
    with open(os.path.join(base, "templates", "report.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(md)
    with open(os.path.join(base, "schema", "report.schema.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(schema(skill, cfg["prefix"]), fh, indent=2)
        fh.write("\n")
    print("wrote", skill)

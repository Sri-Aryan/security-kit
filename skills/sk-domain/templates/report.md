<!--
SecurityKit report template. Fill every {{placeholder}}; keep headings and their order.
Repeat the FINDING block once per confirmed finding, sorted by severity then check ID.
If a severity group has no findings, write "None." under its heading.
Never include secrets: redact to the first 4 characters + "…".
-->
# Domain & DNS Security Report

**Project:** {{project_name}}
**Generated:** {{generated_at}} by SecurityKit sk-domain {{skill_version}}
**Scope:** {{scope}}  <!-- "full checklist" or "section: <name>" -->
**Modes:** static {{static_mode}} · dynamic {{dynamic_status}}

## Score: {{score}}/100

| Critical | High | Medium | Low | Passed | Skipped | Needs review |
|---:|---:|---:|---:|---:|---:|---:|
| {{critical}} | {{high}} | {{medium}} | {{low}} | {{passed_count}} | {{skipped_count}} | {{review_count}} |

Score = 100 − 25×Critical − 10×High − 4×Medium − 1×Low (minimum 0).
{{candidates_reviewed}} candidates reviewed, {{candidates_rejected}} rejected as false positives.

### Top fixes

1. {{top_fix_1}}
2. {{top_fix_2}}
3. {{top_fix_3}}

---

## Findings

### Critical

<!-- FINDING -->
#### [{{check_id}}] {{title}}

| | |
|---|---|
| **Severity** | {{severity}} |
| **Location** | `{{file}}:{{line}}`  <!-- or: `{{method}} {{url}}` → {{status}} --> |
| **References** | OWASP {{owasp}} · {{cwe}} |

**Evidence**

```{{lang}}
{{evidence_snippet}}
```

**Impact.** {{impact}}

**Fix.** {{fix}}

**Regression test.** {{regression_test}}
<!-- /FINDING -->

### High

### Medium

### Low

---

## Needs manual review

<!-- Plausible issues that could not be proven with evidence. Not counted in the score. -->

| Check | Where | Why it could not be confirmed |
|---|---|---|
| {{check_id}} | {{location}} | {{reason}} |

## Checks passed

| Check | Title | Note |
|---|---|---|
| {{check_id}} | {{title}} | {{note}} |

## Checks skipped

| Check | Title | Reason |
|---|---|---|
| {{check_id}} | {{title}} | {{reason}} <!-- e.g. "dynamic, no endpoint URL", "not applicable: <why>" --> |

## Domains and records

Domains: {{domains}}. DNS in code: {{dns_in_code}}. SPF/DMARC/CAA: {{mail_auth}}.

| Record | Type | Target / value | Source | Findings |
|---|---|---|---|---|
| `{{name}}` | {{type}} | `{{value}}` | {{source}} | {{finding_ids}} |

---

*A clean report is not a guarantee of security. SecurityKit finds common, checkable issues;
it does not replace a professional penetration test or threat model. All analysis ran locally;
no code left this machine.*

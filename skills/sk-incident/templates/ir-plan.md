<!--
SecurityKit incident response plan template. Fill every {{placeholder}} from the repo evidence and the user's answers.
Keep it short enough to use at 3 a.m. Mark unknowns as "TBD (owner)" instead of guessing.
-->
# Incident Response Plan: {{system_name}}

**Owner:** {{plan_owner}} · **Last reviewed:** {{review_date}} · **Next exercise:** {{next_exercise}}

## 1. Contacts

| Role | Who | How to reach (24/7) |
|---|---|---|
| Incident commander | {{ic}} | {{ic_contact}} |
| Security lead | {{security_lead}} | {{security_contact}} |
| Engineering on call | {{oncall_rotation}} | {{paging_tool}} |
| Legal / privacy | {{legal}} | {{legal_contact}} |
| Communications | {{comms}} | {{comms_contact}} |

External reporting address: {{security_email}} (published in SECURITY.md / security.txt).

## 2. Severity levels

| Level | Examples | Response |
|---|---|---|
| SEV1 | confirmed data breach, active account takeover at scale, production compromise | page immediately, all hands, notify legal |
| SEV2 | leaked production secret, exploitable vulnerability with no evidence of use | page on call, fix within hours |
| SEV3 | suspicious activity, low-impact vulnerability | ticket, next business day |

## 3. First hour checklist

1. Open an incident channel/document; name the incident commander; start a timeline (UTC).
2. Preserve evidence: snapshot logs ({{log_locations}}), don't wipe affected hosts.
3. Contain (pick what applies): {{containment_levers}}
4. Assess scope: which data, users, tenants, time window.
5. Decide notification duties (section 6) and start the clock.

## 4. Runbooks

| Scenario | Steps |
|---|---|
| Leaked secret / key | identify where it's used ({{secret_inventory}}), rotate, revoke old, search logs for use, purge from git history |
| Account takeover | lock account, revoke sessions/tokens ({{revoke_procedure}}), reset credentials/MFA, review actions taken |
| Data exposure | stop the exposure, determine records and people affected, preserve access logs |
| Compromised dependency / build | pin known-good versions, rebuild from clean runners, rotate CI secrets, review deploys |
| Ransomware / destructive action | isolate, restore from backups ({{backup_procedure}}), rotate all credentials |

## 5. Recovery

Backups: {{backup_scope}} · RPO {{rpo}} · RTO {{rto}} · Last successful restore test: {{last_restore_test}}.

## 6. Notification duties

| Who | When | Template |
|---|---|---|
| {{regulator}} | {{deadline}} | {{template_location}} |

## 7. After the incident

Post-incident review within {{review_window}}: timeline, root cause, what worked, action items with owners and dates.

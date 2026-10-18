# Incident readiness checklist

Source of truth for `sk-incident` check IDs. Covers whether a team could detect, contain, investigate and recover from
a security incident in the system this repository builds: a written plan and runbooks, roles and contacts, detection
and alerting, evidence (logs and audit trails), containment levers (revoking sessions and tokens, rotating secrets,
disabling features), backups and restore, communication and notification duties, and practice. Most evidence is
organizational; the repository shows part of it and the rest comes from the user. Based on the OWASP Incident Response
and Logging cheat sheets and NIST SP 800-61 (incident handling).

Columns: **Mode** S = static (repo evidence), M = manual (ask the user). OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| IR-PLAN-001 | A written incident response plan exists with severity levels, roles, escalation and runbooks for likely incidents (leaked secret, account takeover, data exposure, compromised dependency, ransomware) | S+M | High | A09 | CWE-1059 |
| IR-CONTACT-001 | Internal on-call and external reporting contacts are defined and published (security contact, SECURITY.md/security.txt) | S+M | Medium | A09 | CWE-1059 |
| IR-ALERT-001 | Security-relevant alerts reach a human who is on call (paging integration, alert rules for auth anomalies, errors, admin actions) | S+M | High | A09 | CWE-778 |
| IR-AUDIT-001 | Logs and audit trails needed for investigation exist, are retained long enough, and can't be altered by an attacker with app access | S+M | High | A09 | CWE-778 |
| IR-REVOKE-001 | Containment levers exist and are tested: revoke all sessions/tokens (per user and globally), disable accounts, block API keys, feature-flag off risky features | S+M | High | A07 | CWE-613 |
| IR-ROTATE-001 | Every secret and key can be rotated quickly with a documented procedure (inventory of secrets, owners, rotation steps) | S+M | High | A07 | CWE-324 |
| IR-BACKUP-001 | Backups exist for critical data, are protected from the production credentials that could delete them, and restores are tested against RPO/RTO targets | S+M | High | A05 | CWE-693 |
| IR-NOTIFY-001 | Notification duties (regulators, customers, partners, payment brands) and deadlines are known, with templates ready | M | Medium | A09 | CWE-1059 |
| IR-PRACTICE-001 | The plan is exercised (tabletop or drill) at least yearly and after major changes; lessons learned are tracked | M | Medium | A09 | CWE-1059 |

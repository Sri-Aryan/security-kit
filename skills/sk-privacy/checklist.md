# Privacy and personal-data checklist

Source of truth for `sk-privacy` check IDs. Covers how an application collects, stores, exposes, shares, keeps and
deletes personal data, in any stack: data inventory, minimization, field encryption, exposure in URLs, responses,
client storage and logs, third-party sharing (analytics, ads, support, AI), consent for tracking, data-subject rights
(export, correction, deletion), retention, production data in test environments and data location. It finds
engineering evidence for privacy duties; it is not legal advice. Based on the OWASP User Privacy Protection cheat
sheet and OWASP Top 10 Privacy Risks. `references/guide.md` explains each check.

Columns: **Mode** S = static. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| PRIV-INV-001 | Personal data is inventoried: which fields, where stored (databases, files, caches, logs, backups, third parties), why, and how sensitive | S | Medium | A04 | CWE-359 |
| PRIV-MIN-001 | Only data needed for a stated purpose is collected and kept (no full birth dates, government IDs, precise location or device fingerprints without need) | S | Medium | A04 | CWE-359 |
| PRIV-ENC-001 | Highly sensitive personal data (government IDs, health, financial, biometrics, precise location) is encrypted at field level or tokenized, beyond disk encryption | S | High | A02 | CWE-311 |
| PRIV-EXPOSE-001 | Personal data is not exposed unnecessarily: not in URLs/query strings, not in full-object API responses, not in browser storage, error messages or client-side bundles | S | High | A01 | CWE-359 |
| PRIV-SHARE-001 | Personal data sent to third parties (analytics, ads, CRM, support, email, AI providers) is minimized, pseudonymized where possible, covered by agreements and listed | S | High | A04 | CWE-359 |
| PRIV-CONSENT-001 | Non-essential tracking (analytics, ads pixels, session replay) loads only after consent where the law requires it, and respects withdrawal | S | Medium | A04 | CWE-359 |
| PRIV-DSR-001 | Users can export, correct and delete their data; deletion reaches all copies (database, search indexes, caches, files, third parties, and backups by expiry) | S | Medium | A04 | CWE-359 |
| PRIV-RET-001 | Retention periods exist and are enforced by code (TTL indexes, scheduled purges, log retention), including for inactive accounts | S | Medium | A04 | CWE-359 |
| PRIV-ANON-001 | Production personal data is not copied to development, test or analytics environments without anonymization | S | High | A04 | CWE-359 |
| PRIV-LOCATION-001 | Personal data is stored and processed in the regions the product promises (data residency), and cross-border transfers are known | S | Low | A04 | CWE-359 |

# Privacy engineering guide

Sources: OWASP User Privacy Protection cheat sheet, OWASP Top 10 Privacy Risks, privacy-by-design principles. This is
engineering guidance that supports legal duties (GDPR, CCPA/CPRA, LGPD, PIPEDA, HIPAA...), not legal advice.

The engineering questions are always the same: **what personal data do we have, where does it go, who can see it, and
when does it disappear?**

## Inventory (PRIV-INV-001)

Build a table from the code: field → model/table → sensitivity (contact, financial, government ID, health, location,
children's, biometric) → purpose → stored where (DB, search, cache, files, logs, backups) → shared with whom →
retention. ORM models, migrations, form schemas, API schemas and analytics calls are the sources.

## Collect less, protect more (PRIV-MIN-001, PRIV-ENC-001)

Ask for the minimum: age check instead of birth date, last 4 digits instead of full numbers, city instead of GPS. For
the most sensitive fields add field-level encryption or tokenization (attr_encrypted/Lockbox, Django encrypted
fields, Prisma/TypeORM column transformers with KMS, pgcrypto, a tokenization vault) so a database dump is not a breach.

## Don't leak it (PRIV-EXPOSE-001)

- Not in URLs or query strings (logged everywhere, sent in `Referer`). Use POST bodies or opaque IDs.
- API responses use explicit output schemas, never whole records.
- Not in `localStorage`/`sessionStorage`; not in client bundles; not in error messages or logs (`/sk-logging`).

## Third parties and consent (PRIV-SHARE-001, PRIV-CONSENT-001)

List every processor (analytics, ads, CRM, support chat, email, error tracking, AI providers: see `/sk-ai`). Send an
internal ID instead of email/name; disable IP collection where possible. Where consent is required, load
non-essential scripts only after it (Google Consent Mode, consent-management platforms), and stop on withdrawal.

## Rights and retention (PRIV-DSR-001, PRIV-RET-001)

- **Export**: a machine-readable export of the user's data. **Correction**: editable profile. **Deletion**: one
  function that deletes or anonymizes the user everywhere: main DB (with cascades), search indexes, caches, object
  storage, analytics/CRM (via their deletion APIs), and lets backups expire. Keep only what law requires (invoices),
  documented.
- **Retention**: each data class has a period enforced by code: TTL indexes (`expireAfterSeconds`), scheduled purge
  jobs, bucket lifecycle rules, log retention settings. Inactive accounts too.

## Environments and location (PRIV-ANON-001, PRIV-LOCATION-001)

Development and test use synthetic or anonymized data (Faker, anonymizing dump tools like pg_anonymizer, Snaplet,
Tonic). If production dumps are ever needed for debugging, scrub them first and delete them after. Keep data in the
regions the product promises; know which providers process it elsewhere.

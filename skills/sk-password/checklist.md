# Password security checklist

Source of truth for `sk-password` check IDs. Covers the whole password lifecycle in any language: storage,
verification, policy, change, reset/recovery, brute force and credential stuffing. Based on the OWASP
Password Storage, Forgot Password, Authentication and Credential Stuffing Prevention cheat sheets (and NIST
SP 800-63B). `sk-auth` covers the wider login/session/MFA picture; this skill goes deep on passwords.
`references/guide.md` gives the exact parameters and correct shapes.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP Top 10 2021.

## Storage (STORE)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| PWD-STORE-001 | Passwords are stored only as adaptive one-way hashes (Argon2id, scrypt, bcrypt, PBKDF2), never plaintext, encrypted or fast-hashed (MD5/SHA-*) | S | Critical | A02 | CWE-916 |
| PWD-STORE-002 | Work factors meet OWASP minimums: Argon2id m≥19 MiB, t≥2, p=1 · scrypt N=2^17, r=8, p=1 · bcrypt cost≥10 · PBKDF2-HMAC-SHA256 ≥600,000 (SHA512 ≥220,000) | S | High | A02 | CWE-916 |
| PWD-STORE-003 | Every password has a unique random salt (library-generated); no fixed, global or reused salt | S | High | A02 | CWE-760 |
| PWD-STORE-004 | If a pepper is used, it is stored outside the database (secret manager/HSM), never in code | S | Medium | A02 | CWE-798 |
| PWD-STORE-005 | bcrypt's 72-byte limit is handled safely: no pre-hashing with a raw binary digest (null-byte truncation); if pre-hashing, base64(HMAC-SHA384(pepper, password)) | S | Medium | A02 | CWE-916 |
| PWD-STORE-006 | Hash parameters are stored with the hash (PHC/modular format) and legacy or weak hashes are upgraded on next login | S | Medium | A02 | CWE-916 |
| PWD-STORE-007 | Passwords never appear anywhere else in plaintext: logs, analytics, error reports, queues, emails, caches, audit tables | S | Critical | A09 | CWE-532 |

## Verification (VERIFY)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| PWD-VERIFY-001 | Passwords are checked with the hashing library's verify function (constant time), never `==` on plaintext or hashes, never a database lookup by password | S | High | A07 | CWE-208 |
| PWD-VERIFY-002 | Input length is capped before hashing (e.g. 64–128 characters) so very long passwords cannot be used for denial of service | S | Medium | A04 | CWE-400 |

## Policy (POLICY)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| PWD-POLICY-001 | Minimum length is at least 8 characters (12–15+ recommended, especially without MFA) | S | Medium | A07 | CWE-521 |
| PWD-POLICY-002 | Long passwords (≥ 64) and all characters (Unicode, spaces) are accepted without truncation, trimming or case-folding; no arbitrary composition rules | S | Medium | A07 | CWE-521 |
| PWD-POLICY-003 | New passwords are checked against breached/common password lists | S | Medium | A07 | CWE-521 |
| PWD-POLICY-004 | No forced periodic rotation, password hints, or knowledge-based security questions as a sole mechanism | S | Low | A07 | CWE-640 |
| PWD-POLICY-005 | Password managers work: pasting is allowed and fields have correct `autocomplete` attributes | S | Low | A07 | CWE-521 |

## Change (CHANGE)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| PWD-CHANGE-001 | Changing a password requires the current password, applies the policy, notifies the user and invalidates other sessions and tokens | S | Medium | A07 | CWE-620 |

## Forgot password / recovery (RESET)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| PWD-RESET-001 | Reset requests return the same response and take the same time whether or not the account exists | S+D | Medium | A07 | CWE-204 |
| PWD-RESET-002 | Reset tokens/codes come from a CSPRNG, are long enough to resist guessing, single-use, short-lived, bound to one user, and stored hashed | S | Critical | A07 | CWE-640 |
| PWD-RESET-003 | Reset links use a configured base URL (never the Host header), HTTPS, and the reset page sets `Referrer-Policy: no-referrer` | S | High | A07 | CWE-640 |
| PWD-RESET-004 | Reset requests and token/code attempts are rate-limited (per account and source) or protected by CAPTCHA | S | High | A07 | CWE-307 |
| PWD-RESET-005 | No account changes or lockout before a valid token; after reset: no auto-login, all sessions and outstanding tokens invalidated, user notified | S | Medium | A07 | CWE-613 |

## Brute force and credential stuffing (BRUTE)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| PWD-BRUTE-001 | Login resists brute force and credential stuffing: per-account and per-source throttling, MFA availability, breached-credential detection, anomaly detection | S+D | High | A07 | CWE-307 |
| PWD-BRUTE-002 | Lockout cannot be abused to deny service to legitimate users (soft lock, CAPTCHA, notification) | S | Low | A07 | CWE-645 |

## Transport and defaults (TX / DEFAULT)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| PWD-TX-001 | Passwords travel only in POST bodies over TLS, never in URLs or query strings | S | Medium | A02 | CWE-598 |
| PWD-DEFAULT-001 | No default, hardcoded or shared account passwords; initial passwords must be changed at first login | S | Critical | A07 | CWE-1392 |

## Tests (TEST)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| PWD-TEST-001 | Tests cover hash format/parameters, legacy upgrade, policy limits, reset token expiry/reuse, session invalidation after change/reset, and throttling | S | Low | A07 | CWE-1125 |

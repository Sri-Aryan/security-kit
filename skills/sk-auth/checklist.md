# Authentication security checklist

Source of truth for `sk-auth` check IDs. Concepts apply to any language, framework or identity setup
(local passwords, sessions, SSO/social login, MFA). Tokens (JWT, API keys, refresh tokens) are covered
by `sk-tokens`; secrets by `sk-secrets`. `references/guide.md` explains how to verify and fix each check.

Columns: **Mode** S = static, D = dynamic, S+D = both. OWASP = OWASP API Top 10 2023 / Top 10 2021.

## Password storage and policy (PWD)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AUTH-PWD-001 | Passwords are hashed with a slow, salted, adaptive algorithm (Argon2id, scrypt, bcrypt, PBKDF2), never a fast hash (MD5/SHA-*) or reversible encryption | S | Critical | A02 | CWE-916 |
| AUTH-PWD-002 | Hash work factors are adequate (bcrypt cost ≥ 10, PBKDF2-SHA256 ≥ 600k iterations, scrypt N ≥ 2^15, Argon2id ≥ 19 MiB) | S | High | A02 | CWE-916 |
| AUTH-PWD-003 | Passwords are never stored or persisted in plaintext (including in logs, caches, queues or audit tables) | S | Critical | A02 | CWE-256 |
| AUTH-PWD-004 | Password checks use the library's verify function (constant time), never `==` on plaintext or on hashes | S | High | A07 | CWE-208 |
| AUTH-PWD-005 | Password policy: minimum length ≥ 8 (12+ recommended), long passphrases allowed (≥ 64), breached-password check, no composition rules that weaken entropy | S | Medium | A07 | CWE-521 |
| AUTH-PWD-006 | Changing a password requires the current password and invalidates other sessions | S+D | Medium | A07 | CWE-620 |

## Account enumeration (ENUM)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AUTH-ENUM-001 | Login gives the same response (message, status, timing) for unknown user and wrong password | S+D | Medium | A07 | CWE-204 |
| AUTH-ENUM-002 | Registration and password reset do not reveal whether an account exists | S+D | Medium | A07 | CWE-204 |

## Brute force (BRUTE)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AUTH-BRUTE-001 | Login is rate-limited per account and per source, with progressive delay or lockout | S+D | High | API4 | CWE-307 |
| AUTH-BRUTE-002 | One-time codes (MFA, email/SMS OTP, reset codes) have attempt limits and expiry | S+D | High | API4 | CWE-307 |
| AUTH-BRUTE-003 | Lockout cannot be abused to lock out other users (soft lock, CAPTCHA, notify) | S | Low | A07 | CWE-645 |

## Password reset and account recovery (RESET)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AUTH-RESET-001 | Reset / verification / magic-link tokens come from a CSPRNG with ≥ 128 bits of entropy | S | Critical | A07 | CWE-640 |
| AUTH-RESET-002 | Reset tokens are single-use, expire quickly (≤ 1 hour), and are stored hashed | S | High | A07 | CWE-640 |
| AUTH-RESET-003 | Reset and verification links are built from a configured base URL, never the request's Host header | S | High | A07 | CWE-640 |
| AUTH-RESET-004 | Completing a reset invalidates existing sessions and outstanding reset tokens | S | Medium | A07 | CWE-613 |

## Multi-factor authentication (MFA)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AUTH-MFA-001 | MFA is enforced server-side on every login path (API, mobile, SSO callback, "remember device", password reset) | S | High | A07 | CWE-308 |
| AUTH-MFA-002 | MFA secrets and backup codes are protected at rest; codes are single-use and checked within a narrow window | S | Medium | A07 | CWE-287 |

## Sessions (SESS)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AUTH-SESS-001 | The session identifier is regenerated on login and privilege change (no session fixation) | S | High | A07 | CWE-384 |
| AUTH-SESS-002 | Logout invalidates the session server-side (not only the cookie) | S+D | Medium | A07 | CWE-613 |
| AUTH-SESS-003 | Session cookies are `HttpOnly`, `Secure` and `SameSite` (Lax or Strict) | S+D | Medium | A05 | CWE-1004 |
| AUTH-SESS-004 | Sessions have idle and absolute timeouts appropriate to the data | S | Medium | A07 | CWE-613 |
| AUTH-SESS-005 | "Remember me" uses a separate, revocable, rotating token, never the password or a never-expiring session | S | Medium | A07 | CWE-539 |

## Credential handling (CRED)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AUTH-CRED-001 | Credentials and one-time codes are never sent in URLs or query strings | S | High | A04 | CWE-598 |
| AUTH-CRED-002 | Credentials and authentication request bodies are never logged | S | High | A09 | CWE-532 |
| AUTH-CRED-003 | No default, hardcoded or backdoor accounts | S | Critical | A07 | CWE-798 |

## Registration, account changes, SSO (REG / ACCT / SSO)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AUTH-REG-001 | Registration cannot set privileged fields (role, verified, plan) and requires email/phone verification before sensitive use | S | High | API3 | CWE-915 |
| AUTH-ACCT-001 | Sensitive account changes (email, password, MFA settings, recovery options) require re-authentication and notify the user | S | Medium | A07 | CWE-306 |
| AUTH-SSO-001 | Social/SSO login links accounts only on a verified email (`email_verified`) from a trusted provider; state/nonce validated | S | High | A07 | CWE-287 |

## Tests (TEST)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AUTH-TEST-001 | Tests cover wrong password, unknown user, lockout, reset token expiry and reuse, session regeneration and logout | S | Low | A07 | CWE-1125 |

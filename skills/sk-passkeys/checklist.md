# Passwordless authentication checklist

Source of truth for `sk-passkeys` check IDs. Covers passwordless sign-in: passkeys / WebAuthn (SimpleWebAuthn,
py_webauthn, python-fido2, go-webauthn, webauthn4j, Yubico java-webauthn-server, webauthn-rs, Fido2NetLib, and the
passkey features of Better Auth, Auth.js, Hanko and similar), magic links, and one-time codes sent by email or SMS.
Based on the W3C WebAuthn Level 3 specification, the FIDO Alliance passkey guidance, NIST SP 800-63B and the OWASP
Authentication and Forgot Password cheat sheets. `references/guide.md` explains each check.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| PASSKEY-CHAL-001 | WebAuthn challenges are ≥16 random bytes from a CSPRNG, stored server-side per ceremony and session, single-use and short-lived | S | High | A07 | CWE-294 |
| PASSKEY-ORIGIN-001 | Expected origin(s) and RP ID are server configuration, never derived from the request's Origin/Host | S | High | A07 | CWE-346 |
| PASSKEY-VERIFY-001 | Registration and authentication responses are verified with a maintained library; the server never trusts a client-reported result | S | Critical | A07 | CWE-347 |
| PASSKEY-UV-001 | User verification is required when the passkey is the only factor | S | Medium | A07 | CWE-308 |
| PASSKEY-CRED-001 | The asserted credential is looked up server-side and must belong to the account being signed into (userHandle checked for discoverable credentials) | S | High | A07 | CWE-639 |
| PASSKEY-COUNTER-001 | The signature counter is stored and checked for regressions (allowing 0 for synced passkeys) | S | Low | A07 | CWE-287 |
| PASSKEY-REG-001 | Adding a passkey requires the account's session (with recent re-authentication); `excludeCredentials` prevents duplicates | S | High | A07 | CWE-306 |
| PASSKEY-RECOVERY-001 | Fallback and recovery (email/SMS codes, passwords, support) are not weaker than the passkey; removing a passkey requires re-authentication and notifies the user | S | Medium | A07 | CWE-640 |
| PASSKEY-MAGIC-001 | Magic-link tokens are ≥128-bit CSPRNG values, stored hashed, single-use, expire within minutes and are bound to the requesting email | S | High | A07 | CWE-640 |
| PASSKEY-MAGIC-002 | Opening a magic link does not sign in by itself: a user action (POST) completes it, ideally in the browser that requested it | S | Medium | A07 | CWE-287 |
| PASSKEY-MAGIC-003 | Links in emails are built from a configured base URL, never the request's Host header | S | High | A07 | CWE-640 |
| PASSKEY-OTP-001 | One-time codes come from a CSPRNG, have ≥6 digits, expire, are invalidated after use, and attempts are limited per code and per account | S+D | High | A07 | CWE-307 |
| PASSKEY-ENUM-001 | Passwordless request endpoints respond the same whether or not the account exists | S+D | Low | A07 | CWE-204 |

# Passwordless authentication guide

Sources: W3C Web Authentication Level 3, FIDO Alliance passkey guidance, SimpleWebAuthn and py_webauthn docs, NIST SP
800-63B (out-of-band and look-up secrets), OWASP Authentication, Forgot Password and Multi-Factor Authentication cheat
sheets.

## Passkeys / WebAuthn

A ceremony is: server creates **options** (with a random challenge) → browser/OS signs → server **verifies** the
response against what it stored. Almost every bug is the server trusting something from the client instead of its own
stored state.

| Check | Confirm | Good practice |
|---|---|---|
| PASSKEY-CHAL-001 | Where is the challenge created, stored and deleted? | Library-generated (or `crypto.randomBytes(32)`), stored in the server session/DB for this ceremony, deleted after one verification attempt, expires in ~5 min. |
| PASSKEY-ORIGIN-001 | Where do `expectedOrigin`/`expectedRPID` come from? | Constants from config (`https://app.acme.com`, `acme.com`), plus native-app origins (`android:apk-key-hash:…`) if used. |
| PASSKEY-VERIFY-001 | Is a maintained library doing verification? | `verifyRegistrationResponse` / `verifyAuthenticationResponse` (SimpleWebAuthn), `verify_*_response` (py_webauthn), go-webauthn `FinishLogin`, etc. Never parse CBOR/clientDataJSON yourself; never accept `{ verified: true }` from the client. |
| PASSKEY-UV-001 | Is the passkey the only factor? | `userVerification: 'required'` in options **and** `requireUserVerification: true` on verify. |
| PASSKEY-CRED-001 | How is the credential found? | Look up by credential ID; with a username-first flow ensure it belongs to that user; for usernameless flows take the user from the credential and compare `userHandle`. |
| PASSKEY-COUNTER-001 | Is `newCounter` stored? | Store and compare; allow 0 for synced passkeys (they don't count). Flag a decrease. |
| PASSKEY-REG-001 | Who can add a passkey to an account? | Only the signed-in owner, after recent re-auth (or during account creation); `excludeCredentials` from existing credentials; notify the user. |
| PASSKEY-RECOVERY-001 | What if the passkey is lost? | Recovery as strong as possible (another passkey, recovery codes, verified email with delay + notification); account changes require re-auth. |

## Magic links

| Check | Good practice |
|---|---|
| PASSKEY-MAGIC-001 | 32 random bytes (`crypto.randomBytes(32).toString('base64url')`, `secrets.token_urlsafe(32)`); store a SHA-256 hash; single use; expiry ≤ 15 min; tied to the email/user that requested it; invalidate older links. |
| PASSKEY-MAGIC-002 | Email security scanners (Outlook Safe Links, Mimecast…) fetch links before users click. A GET that signs in can log the scanner in or burn the token. Render a confirmation page; complete on POST. Bind to the requesting browser (a cookie set when the link was requested) to stop forwarded-link and phishing attacks, or show a code to type instead. |
| PASSKEY-MAGIC-003 | Build URLs from `APP_URL` config, never `req.headers.host` / `X-Forwarded-Host` (host header poisoning sends the victim a link to the attacker's domain carrying a valid token). |

## One-time codes (email / SMS)

PASSKEY-OTP-001: `crypto.randomInt(0, 1_000_000)` / `secrets.randbelow(10**6)`, zero-padded, ≥ 6 digits; expiry
5–10 minutes; delete after success; **attempts limited per code (e.g. 5) and per account/IP per hour**, then require a
new code; constant-time comparison. SMS-specific cost abuse is in `/sk-email` (SMS pumping).

## Enumeration (PASSKEY-ENUM-001)

"Send me a link/code" must answer the same for known and unknown emails ("If an account exists, we sent a link"), with
similar timing (send asynchronously).

## Dynamic checks (only with `--base-url`, test accounts the user owns)

Replay a captured authentication response (expect failure); submit with a different Origin header (expect failure);
reuse a magic link twice; request a link with a forged `Host`/`X-Forwarded-Host` and inspect the email (own inbox
only); try 10 wrong codes and confirm lock-out.

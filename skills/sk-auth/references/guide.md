# Authentication guide: how to verify and fix each concept

Language-neutral. Every authentication system answers the same questions: how are secrets stored, how is a
guess slowed down, how is a forgotten secret recovered, how is a second factor enforced, and how is the
resulting session created, protected and ended. Find the code for each, then check it against the shapes below.

---

## Password storage (AUTH-PWD-001…004)

**Correct shape (any language):**
```
register:  hash = KDF(password)                 # Argon2id / scrypt / bcrypt / PBKDF2 via a maintained library
           store(hash)                          # the library embeds salt + parameters in the hash string
login:     ok = KDF.verify(hash, candidate)     # constant-time verify from the same library
           if ok and KDF.needs_rehash(hash): store(KDF(candidate))   # upgrade parameters over time
```
**Verify.** Find where passwords are written (registration, admin user creation, seeding, password change,
reset) and where they are checked (login, re-auth, API basic auth). Every write must go through the KDF;
every check through its `verify`. Look for passwords leaking into logs, analytics, queues or audit tables.

**Fix.** Use the language's maintained library (argon2/bcrypt packages, `passlib`, Spring `PasswordEncoder`,
ASP.NET `PasswordHasher`, PHP `password_hash`). Migrate legacy hashes on next login (verify old, store new).

## Policy (AUTH-PWD-005/006)

NIST 800-63B: minimum 8 (prefer 12+), allow at least 64 characters and any characters, check against breached
password lists, no forced periodic rotation, no composition rules. Password change: require the current
password, then revoke other sessions and refresh tokens.

## Enumeration (AUTH-ENUM-*)

**Verify.** Compare the unknown-user and wrong-password branches of login: same status, same body, and
similar timing (if the unknown-user branch skips the hash check, it answers faster; run a dummy verify).
Reset: always "if the account exists, we sent a link". Registration: confirm by email instead of saying
"already registered" on the page.

## Brute force (AUTH-BRUTE-*)

**Verify.** Find the limiter on login, OTP/MFA verification, reset-code verification and signup. Check the key:
per account *and* per source (IP alone is bypassed by botnets; account alone enables lockout of others). Check
the limiter trusts `X-Forwarded-For` only from known proxies. Check limits outside the repo (gateway, WAF)
with the user before confirming a finding.

**Fix.** Rate limit + progressive delay per account and per IP; attempt counters on codes (e.g. 5 tries then
the code is invalidated); CAPTCHA or soft lock instead of hard lockout.

## Reset and recovery (AUTH-RESET-*)

**Correct shape:**
```
token = CSPRNG(32 bytes) -> url-safe string          # never Math.random / uuid1 / timestamps
store(hash(token), user_id, expires=now+30..60min, used=false)
link  = CONFIG.APP_URL + "/reset/" + token           # never the request Host header
on submit: find by hash(token); check not expired, not used; set new password; mark used;
           revoke all sessions + refresh tokens; notify the user
```
Same for email verification, magic links and invitations.

## MFA (AUTH-MFA-*)

**Verify.** List every way to obtain a session: password login, API login, mobile login, SSO callback,
"remember this device", password reset completion, account recovery, admin impersonation. MFA must be
required on each, server-side, before a full session is issued (use a "pending MFA" state, not a full session
plus a front-end redirect). TOTP: allow ±1 step, block reuse of the same code, rate-limit attempts. Backup
codes: hashed, single-use. Disabling MFA: requires re-authentication.

## Sessions (AUTH-SESS-*)

**Verify.** On successful login (and on privilege change), is the session ID regenerated? On logout, is the
server-side session destroyed / the token revoked, not just the cookie cleared? Cookies: `HttpOnly`, `Secure`,
`SameSite=Lax|Strict`, narrow `Path`/`Domain`. Timeouts: idle (e.g. 15–30 min for sensitive apps) and absolute
(e.g. 8–24 h). "Remember me": a separate random token stored hashed server-side, rotated on use, revocable.

## Credential handling (AUTH-CRED-*)

Credentials only in POST bodies over TLS, never in URLs (they end up in logs, history, Referer). Do not log
request bodies of auth endpoints. Remove default accounts and test backdoors (`if user == "admin" && pw == ...`).

## Registration, account changes, SSO (AUTH-REG / ACCT / SSO)

Registration must ignore client-supplied `role`, `isAdmin`, `verified`, `plan`. Email/phone changes:
re-authenticate, confirm the new address, notify the old one. SSO: validate `state` (CSRF) and `nonce`, verify
the ID token (`iss`, `aud`, `exp`, signature), and link to an existing account only when the provider says the
email is verified, or require the user to log in to the existing account first.

## Test ideas (AUTH-TEST-001)

Unknown user vs wrong password produce identical responses; N+1 failed logins are throttled; a reset token
works once, expires, and cannot be reused; the session cookie changes after login; logout makes the old cookie
useless; MFA cannot be skipped by calling the post-login endpoint directly.

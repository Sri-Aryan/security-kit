# Password guide: parameters, shapes and fixes

Sources: OWASP Password Storage, Forgot Password, Authentication and Credential Stuffing Prevention cheat
sheets; NIST SP 800-63B. Language-neutral: use the platform's maintained library for the chosen algorithm.

---

## Storage (PWD-STORE-*)

### Algorithms and minimum parameters (OWASP Password Storage Cheat Sheet)

| Algorithm | When | Minimum parameters |
|---|---|---|
| **Argon2id** | preferred | m = 19 MiB (19456 KiB), t = 2, p = 1 — or equivalent: m=47104/t=1, m=12288/t=3, m=9216/t=4, m=7168/t=5 |
| **scrypt** | if Argon2id unavailable | N = 2^17 (128 MiB), r = 8, p = 1 (or N=2^16/p=2, N=2^15/p=3, N=2^14/p=5, N=2^13/p=10) |
| **bcrypt** | legacy systems | cost ≥ 10 (as high as login latency allows); input limit 72 bytes |
| **PBKDF2** | FIPS-140 required | HMAC-SHA256 600,000 · HMAC-SHA512 220,000 · HMAC-SHA1 1,300,000 (legacy only) |

Target well under a second per hash on production hardware and raise parameters over time.

### Correct shape
```
store:   hash = KDF.hash(password)                 # library generates a unique salt, embeds params (PHC string)
verify:  ok = KDF.verify(stored_hash, candidate)   # constant time; never compare strings or query by password
         if ok and KDF.needs_rehash(stored_hash): store(KDF.hash(candidate))   # parameter upgrades
```
- **Salt**: unique and random per password; let the library do it. A hardcoded "app salt" is not a salt.
- **Pepper** (optional): one secret for all passwords, kept in a secret manager/HSM, never in code or the
  database; applied as HMAC before hashing or after. Rotating it forces resets, so plan for that.
- **bcrypt pre-hashing**: avoid. If unavoidable, `bcrypt(base64(HMAC-SHA384(pepper, password)))`, never a raw
  binary digest (NUL bytes truncate input and enable password shucking).
- **Legacy hashes** (MD5/SHA-1/unsalted): wrap them (`bcrypt(md5(pw))`) immediately, then replace with a direct
  hash at the next successful login; expire long-inactive accounts and force a reset.
- **Nowhere else**: passwords never in logs, analytics, error trackers, queues, emails, caches or audit rows.
  Check request-logging middleware for auth routes.

## Verification and input (PWD-VERIFY-*)

Accept full Unicode; do not trim, case-fold or otherwise change the password. Cap length before hashing
(64–128 characters) to bound CPU cost. bcrypt's 72-byte limit means very long passwords should be rejected
or safely pre-hashed, not silently truncated.

## Policy (PWD-POLICY-*), following NIST SP 800-63B

- Minimum 8 characters (12–15+ recommended; 15 for single-factor systems in the latest NIST draft).
- Maximum at least 64; allow spaces, Unicode, emoji.
- Check new passwords against breached/common lists (k-anonymity HIBP API or an offline list).
- No composition rules, no periodic forced changes, no hints, no knowledge-based questions as a sole factor.
- Allow paste and password managers (`autocomplete="new-password"` / `"current-password"`).

## Change (PWD-CHANGE-001)

Require the current password (or recent re-authentication), apply the policy, notify the user out of band,
invalidate all other sessions and refresh tokens.

## Forgot password (PWD-RESET-*)

```
request(email):
    always: respond "If the account exists, we sent instructions" (same status, same timing: do the work async)
    rate-limit per account and per IP / CAPTCHA
    if account: token = CSPRNG(≥ 32 bytes, url-safe)
                store(user, sha256(token), expires = now + 15–60 min, used = false)
                email link = CONFIG.APP_URL + "/reset?token=" + token      # never the Host header; HTTPS
reset page:   Referrer-Policy: no-referrer
submit(token, new_password):
    row = find(sha256(token)); reject if missing, expired or used           # rate-limit attempts
    apply password policy (entered twice); store new hash; mark token used; delete other tokens
    revoke all sessions/refresh tokens; notify user; send to the normal login (no auto-login)
```
PINs (6–12 digits via SMS/side channel) create a restricted session that only allows the reset. Do not lock
accounts in response to reset requests. After suspected compromise, recover with previously established
evidence (saved recovery codes), not recently changed contact details.

## Brute force and credential stuffing (PWD-BRUTE-*)

Throttle per account and per source with progressive delays; offer/require MFA; detect breached credentials
and unusual patterns (many accounts from one IP, many IPs on one account); use CAPTCHA as a step-up rather
than a wall; prefer soft locks with notification over hard lockouts that attackers can abuse.

## Defaults and transport (PWD-DEFAULT-001, PWD-TX-001)

No built-in accounts with known passwords; generated initial passwords must be changed on first login.
Passwords only in POST bodies over TLS, never in URLs.

## Test ideas (PWD-TEST-001)

Stored hash starts with `$argon2id$v=19$m=19456,t=2,p=1` (or the chosen algorithm/params); a legacy hash is
upgraded after login; a 129-character password is rejected quickly; a reset token works once, expires, and
the old session cookie stops working afterwards; the reset request for unknown and known emails returns
identical responses.

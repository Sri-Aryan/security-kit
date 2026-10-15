# Token guide: how to verify and fix each concept

Language-neutral. A token is a bearer credential: whoever holds it *is* the user. Three questions decide its
safety: **can it be forged** (signature, algorithm, key, randomness), **how long does it work and can it be
stopped** (expiry, rotation, revocation), and **where can it leak** (URLs, logs, browser storage, database).

---

## Inventory first

List every token type: session ID, JWT access token, refresh token, API key, personal access token, CSRF
token, webhook secret, signed URLs, invitation/download links. For each record: where it is **issued**,
where it is **verified**, its **lifetime**, where the client **stores** it, and how the server **stores** it.
This table is the report's inventory.

## Signed tokens / JWT (TOK-JWT-*)

**Correct verification (any library):**
```
claims = verify(token,
                key        = key_for(kid)  from a local, trusted key set (or the IdP's configured JWKS URL),
                algorithms = ["RS256"]     exactly what you issue, never from the token,
                issuer     = "https://id.example.com",
                audience   = "my-api",
                require    = ["exp", "iat", "sub"],
                leeway     = <= 60s)
```
**Verify.** Every route that trusts a token goes through that verify call (or middleware) before reading
claims. No `decode()` on the server path. Algorithms pinned, no `none`, no HS/RS mixing. HS keys ≥ 32
random bytes from config/secret manager. `kid` only selects from a fixed key set, never a file path, SQL
lookup or URL. `jku`/`x5u`/`jwk` headers ignored. `exp` present and checked, access tokens short (5–60 min).
Payload: identifiers and roles only, no secrets or PII.

**Revocation (TOK-JWT-008).** Pick one: short access tokens + revocable refresh tokens; a denylist of `jti`
until expiry; or a per-user `token_version` claim checked on each request and bumped on logout/password change.

## Generation and comparison (TOK-GEN-*)

Generate with the platform CSPRNG (`crypto.randomBytes`/`randomUUID`, `secrets.token_urlsafe`, `crypto/rand`,
`SecureRandom`, `RandomNumberGenerator`), ≥ 16 bytes (128 bits). Never `Math.random`, `random`, `math/rand`,
`uuid1`, timestamps or counters. Compare with a constant-time function, or better: store `sha256(token)`
and look up by hash, which removes timing concerns and protects the database copy.

## Storage and transport (TOK-STORE-*)

- **Browser:** prefer `HttpOnly; Secure; SameSite` cookies. Tokens in `localStorage` are readable by any XSS.
  If an SPA must hold a token, keep it in memory and refresh through an `HttpOnly` cookie.
- **URLs:** never put tokens in query strings, redirects or links (logs, history, `Referer`, analytics).
  Exception: single-use, short-lived email links.
- **Logs:** never log tokens, `Authorization` headers or full request headers; add redaction to the logger.
- **Database:** store API keys and refresh tokens as hashes (sha256 is fine for high-entropy random tokens);
  show the raw key to the user once.

## Refresh tokens (TOK-REFRESH-*)

```
on refresh(rt):  row = find_by_hash(rt)
                 if not row or row.revoked: revoke_family(row.family); fail       # reuse detection
                 if row.expires_at < now: fail
                 row.revoked = true
                 new = issue(user, family=row.family, absolute_expiry=row.family_expiry)
```
Revoke all refresh tokens on logout (that device) and on password change (all devices).

## API keys (TOK-KEY-*)

Scopes per key, expiry dates, individual revocation, last-used tracking, per-key rate limits, an
identifiable prefix (`sk_live_…`) so secret scanners can find leaked keys, and acceptance only from headers.

## Test ideas (TOK-TEST-001)

Tamper one payload byte → 401. Header `alg: none` with no signature → 401. Re-sign with HS256 using the RSA
public key → 401. Expired token → 401. Token for another audience → 401. Reuse an already-rotated refresh token
→ 401 and the family is revoked. Revoked API key → 401.

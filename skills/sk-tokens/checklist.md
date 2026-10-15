# Token security checklist

Source of truth for `sk-tokens` check IDs. Covers every bearer credential an application issues or accepts:
JWTs (and other signed tokens), opaque session/access tokens, refresh tokens, API keys, and generic random
tokens. Concepts apply to any language. Password-reset/verification tokens are in `sk-auth`; hardcoded
secrets in `sk-secrets`. `references/guide.md` explains each check.

Columns: **Mode** S = static, D = dynamic, S+D = both. OWASP = OWASP API Top 10 2023 / Top 10 2021.

## Signed tokens / JWT (JWT)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| TOK-JWT-001 | Every token is signature-verified before its claims are trusted (no decode-only) | S+D | Critical | API2 | CWE-347 |
| TOK-JWT-002 | Accepted algorithms are pinned server-side; `none` is rejected; symmetric and asymmetric algorithms are never mixed for one key (key confusion) | S+D | Critical | API2 | CWE-327 |
| TOK-JWT-003 | Signing keys are strong (HS256: ≥ 256 random bits), not hardcoded, and rotatable (`kid`) | S | Critical | API2 | CWE-321 |
| TOK-JWT-004 | Tokens carry `exp`; expiry is enforced; access-token lifetime is short (minutes, not days) | S+D | High | API2 | CWE-613 |
| TOK-JWT-005 | `iss` and `aud` (and `nbf`) are validated, so tokens issued for another service are rejected | S | High | API2 | CWE-287 |
| TOK-JWT-006 | Header parameters (`kid`, `jku`, `x5u`, `jwk`) never choose keys from untrusted locations; `kid` is never used in file paths, SQL or URLs | S | High | API2 | CWE-345 |
| TOK-JWT-007 | Token payloads contain no secrets or unnecessary personal data (JWTs are only encoded, not encrypted) | S | Medium | API3 | CWE-312 |
| TOK-JWT-008 | Tokens can be revoked when needed (logout, password change, compromise): denylist, short lifetime + refresh, or version claim | S | Medium | API2 | CWE-613 |

## Generation and comparison (GEN)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| TOK-GEN-001 | Random tokens, API keys, session IDs, nonces and salts come from a CSPRNG with ≥ 128 bits of entropy | S | Critical | A02 | CWE-338 |
| TOK-GEN-002 | Tokens are compared in constant time (or looked up by hash) | S | Medium | A02 | CWE-208 |

## Storage and transport (STORE)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| TOK-STORE-001 | Browser apps do not keep long-lived tokens in `localStorage`/`sessionStorage` (XSS-readable); prefer `HttpOnly` cookies | S | Medium | A05 | CWE-922 |
| TOK-STORE-002 | Tokens are never put in URLs (query strings, redirects, links): they leak via logs, history and `Referer` | S | High | API2 | CWE-598 |
| TOK-STORE-003 | Tokens and `Authorization` headers are never logged | S | High | A09 | CWE-532 |
| TOK-STORE-004 | Long-lived tokens stored server-side (API keys, refresh tokens) are stored hashed, not in plaintext | S | High | A02 | CWE-522 |

## Refresh tokens (REFRESH)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| TOK-REFRESH-001 | Refresh tokens rotate on every use, and reuse of an old one revokes the whole token family | S | High | API2 | CWE-613 |
| TOK-REFRESH-002 | Refresh tokens have an absolute lifetime, are bound to the user/client, and are revoked on logout and password change | S | Medium | API2 | CWE-613 |

## API keys (KEY)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| TOK-KEY-001 | API keys are scoped (least privilege), expirable, rotatable and individually revocable | S | Medium | API5 | CWE-272 |
| TOK-KEY-002 | API keys are sent in headers, not query strings | S+D | Medium | API2 | CWE-598 |
| TOK-KEY-003 | Key use is attributed and rate-limited per key; keys are identifiable (prefix) for secret scanning | S | Low | API4 | CWE-770 |

## Tests (TEST)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| TOK-TEST-001 | Tests cover: tampered signature, `alg: none`, expired token, wrong audience, reused refresh token, revoked API key | S | Low | API2 | CWE-1125 |

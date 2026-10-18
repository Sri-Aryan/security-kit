# OAuth 2.0 / OIDC guide: how to verify and fix each concept

Sources: OWASP OAuth2 Cheat Sheet (based on RFC 9700, OAuth 2.0 Security BCP), OWASP JSON Web Token Cheat
Sheet. Library-neutral. First decide which **roles** the project plays; most projects are a client
(login with Google/GitHub/Okta/Auth0/Entra ID/Keycloak) and often a resource server (their API accepts the
access tokens). Few run an authorization server.

---

## The client flow, correctly (GRANT, PKCE, STATE, REDIR, OIDC, TOKEN)

```
login:
  verifier  = random(32 bytes);  challenge = BASE64URL(SHA256(verifier))      # PKCE S256
  state     = random(16 bytes);  nonce = random(16 bytes)                      # store all three server-side / in session
  redirect to  AS/authorize?response_type=code&client_id=…&redirect_uri=<FIXED>&scope=<minimal>
               &state=…&nonce=…&code_challenge=…&code_challenge_method=S256

callback:
  if params.state != session.state: reject                                    # CSRF / one-time
  if multiple AS and params.iss != expected_issuer: reject                     # mix-up
  tokens = POST AS/token { grant_type=authorization_code, code, redirect_uri, code_verifier, client auth }
  id = verify(tokens.id_token, AS JWKS, iss=expected, aud=client_id, exp, nonce=session.nonce)
  user = find_by(iss=id.iss, sub=id.sub)       # link by email only if id.email_verified and the provider is trusted
  rotate session; clear state/nonce/verifier; redirect to an allow-listed return path
```

- **Implicit** (`response_type=token`) and **ROPC** (`grant_type=password`) are deprecated: use the flow above
  for every client, including SPAs (via a backend-for-frontend or PKCE in the browser) and native apps
  (loopback/custom-scheme redirect + PKCE).
- **Redirect URI** is a constant from configuration, HTTPS (loopback only for native), registered by exact
  match. Never derive it from the `Host` header or a query parameter.
- **Return-to URLs** after login: allow-list or relative paths only, or the client becomes an open redirector
  that leaks codes/tokens.
- **Tokens in the browser**: avoid `localStorage`. Prefer a BFF that keeps tokens server-side and gives the
  browser an `HttpOnly` session cookie; otherwise keep them in memory.
- **Scopes**: request the minimum; separate tokens per resource server (audience).
- **Refresh tokens**: rotation with reuse detection, or sender-constrained (DPoP / mTLS).

## Client credentials (CLIENT)

Public clients (browser, mobile, desktop) cannot keep secrets. They use PKCE and no secret. Confidential
clients (servers) keep secrets in a secret manager, never in bundles, apps or the repo; prefer
`private_key_jwt` or mTLS over shared secrets. A leaked client secret must be rotated at the provider.

## Resource server (RS)

On **every** request:
```
token  = bearer from Authorization header (never from the query string)
claims = verify(token, AS JWKS, algorithms=[expected], iss=AS, aud=THIS_API, exp)   # or introspect opaque tokens
require scope/permission for THIS action, then object-level authorization for THIS resource
if token is DPoP/mTLS-bound: verify the proof matches the binding
```
A valid token for a different API (wrong `aud`) must be rejected. Scope says what kind of action; it does not
replace object-level checks (user A's token with `orders:read` must not read user B's order).

## Authorization server (AS)

Exact redirect-URI matching (no wildcards, prefixes or substring checks); PKCE supported and enforced, with
downgrade protection; authorization codes single-use (a reused code should revoke tokens issued from it),
short-lived, bound to client and redirect URI; refresh-token rotation; clients cannot set `sub` or claims that
impersonate users; no open redirects on error paths; asymmetric client authentication supported; tokens
audience-restricted. If the project implements this by hand, recommend a maintained AS (Keycloak, Ory Hydra,
Authelia, a managed IdP) instead.

## Transport (TLS)

Issuer, authorize, token, JWKS, userinfo and redirect URIs are all HTTPS. HTTP is only acceptable for loopback
redirects in native apps and local development.

## Test ideas

Callback with a missing or wrong `state` → rejected; code replayed → rejected; `redirect_uri` changed → rejected
by the AS; ID token with wrong `aud` or `nonce` → rejected; API token with another audience → 401; token without
the required scope → 403; return-to `https://evil.example` → ignored.

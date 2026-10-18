# OAuth 2.0 / OpenID Connect checklist

Source of truth for `sk-oauth2` check IDs. A project can play three OAuth roles: **client** (it sends users to
a provider and gets tokens), **resource server** (its API accepts access tokens), and **authorization server**
(it issues tokens). Checks apply per role, in any language or library. Based on the OWASP OAuth2 Cheat
Sheet (RFC 9700 OAuth 2.0 Security Best Current Practice) and the OWASP JSON Web Token Cheat Sheet.
`references/guide.md` explains each check.

Columns: **Mode** S = static. OWASP = OWASP Top 10 2021 / API Top 10 2023.

## Grants (GRANT)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| OAUTH-GRANT-001 | All user-facing clients (web, SPA, native) use Authorization Code with PKCE; the Implicit grant (`response_type=token`) is not used | S | High | A07 | CWE-522 |
| OAUTH-GRANT-002 | The Resource Owner Password Credentials grant is not used (it exposes user credentials to the client) | S | High | A07 | CWE-522 |

## PKCE, state, nonce (PKCE / STATE)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| OAUTH-PKCE-001 | PKCE with `S256` is used per authorization request; the verifier is random per transaction and never sent in the front channel (`plain` not used) | S | High | A07 | CWE-345 |
| OAUTH-STATE-001 | A one-time `state` bound to the user's session is sent and verified on callback (CSRF protection), unless PKCE/nonce already provide it | S | High | A01 | CWE-352 |

## Redirects (REDIR)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| OAUTH-REDIR-001 | Redirect URIs are fixed, exact-match registered values over HTTPS (loopback only for native apps), never built from request data | S | Critical | A01 | CWE-601 |
| OAUTH-REDIR-002 | The client has no open redirector: post-login "return to" URLs are validated against an allow-list or relative paths | S | Medium | A01 | CWE-601 |
| OAUTH-MIXUP-001 | With multiple authorization servers, the client validates `iss` (or uses distinct redirect URIs per server) to prevent mix-up attacks | S | Medium | A07 | CWE-346 |

## OpenID Connect identity (OIDC)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| OAUTH-OIDC-001 | ID tokens are fully validated: signature (provider JWKS), `iss`, `aud` = client ID, `exp`, and `nonce` | S | High | A07 | CWE-347 |
| OAUTH-OIDC-002 | Users are identified by the stable (`iss`, `sub`) pair; email is used for linking only when `email_verified` is true and the provider is authoritative | S | High | A07 | CWE-287 |

## Tokens on the client (TOKEN)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| OAUTH-TOKEN-001 | Access tokens are obtained only from the token endpoint (back channel), never from URL fragments or query strings | S | High | A07 | CWE-598 |
| OAUTH-TOKEN-002 | Refresh tokens are rotated on use (with reuse detection) or sender-constrained (DPoP / mTLS) | S | Medium | A07 | CWE-613 |
| OAUTH-TOKEN-003 | Browser apps do not keep tokens in `localStorage`/`sessionStorage`; prefer a backend-for-frontend with `HttpOnly` cookies | S | Medium | A05 | CWE-922 |
| OAUTH-TOKEN-004 | Requested scopes are minimal, and tokens are audience-restricted to the intended resource server | S | Medium | API5 | CWE-272 |

## Client credentials (CLIENT)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| OAUTH-CLIENT-001 | Client secrets never appear in browser bundles, mobile apps or the repository; public clients use PKCE without a secret | S | Critical | A07 | CWE-798 |
| OAUTH-CLIENT-002 | Confidential clients authenticate to the token endpoint, preferably with asymmetric methods (`private_key_jwt`, mTLS) | S | Low | A07 | CWE-287 |

## Resource server (RS)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| OAUTH-RS-001 | Every request's access token is validated: signature or introspection, `iss`, `aud` = this API, `exp` | S | Critical | API2 | CWE-287 |
| OAUTH-RS-002 | Every request checks that the token's scopes/claims permit this action on this specific resource | S | High | API5 | CWE-285 |
| OAUTH-RS-003 | Sender-constrained tokens (DPoP / mTLS) have their proof validated against the token binding | S | Low | API2 | CWE-294 |

## Authorization server (AS), only if the project issues tokens

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| OAUTH-AS-001 | Redirect URIs are matched exactly (no wildcards, no prefix match); no open redirects; credential-bearing requests are never forwarded | S | Critical | A01 | CWE-601 |
| OAUTH-AS-002 | PKCE is supported and enforced, including downgrade protection (reject a `code_verifier` when no challenge was sent) | S | High | A07 | CWE-345 |
| OAUTH-AS-003 | Authorization codes are single-use, short-lived (≤ 60 s typical) and bound to the client and redirect URI | S | High | A07 | CWE-294 |
| OAUTH-AS-004 | Clients cannot influence `sub`, `client_id` or claims that could be mistaken for a resource owner | S | High | A07 | CWE-290 |

## Transport (TLS)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| OAUTH-TLS-001 | All OAuth endpoints, issuers, JWKS and redirect URIs use TLS | S | High | A02 | CWE-319 |

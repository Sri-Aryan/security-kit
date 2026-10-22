# Auth provider integration checklist

Source of truth for `sk-authprovider` check IDs. Covers how an application integrates a hosted auth service or auth
library: Clerk, Auth0, Auth.js / NextAuth, Better Auth, Lucia, Supabase Auth, Firebase Auth, Kinde, WorkOS, Stack Auth,
Amazon Cognito / Amplify, Stytch, Descope and PropelAuth. The provider handles passwords and sessions; the integration
decides who the app *believes* the user is. Login flows themselves are `/sk-auth`; raw OAuth/OIDC is `/sk-oauth2`.
Based on the providers' security documentation and the OWASP Authentication and Session Management cheat sheets.
`references/guide.md` explains each check.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AUTHP-SERVER-001 | Server code identifies the user from a verified session/token via the provider's server API (`auth()`, `getUser()`/`getClaims()`, `verifyIdToken`), never from a decoded-only token or a client-sent user ID | S+D | Critical | A07 | CWE-287 |
| AUTHP-ROLE-001 | Roles, plans and permissions live where users cannot write them (Clerk `publicMetadata`/`privateMetadata`, Supabase/Auth0 `app_metadata`, custom claims, own table), never in user-editable metadata | S | Critical | A01 | CWE-269 |
| AUTHP-MW-001 | Middleware/route protection actually protects: Clerk `auth.protect()` on a matcher, public-route lists don't include all of `/api`, default-deny for new routes | S | High | A01 | CWE-284 |
| AUTHP-WEBHOOK-001 | Provider webhooks and auth hooks that create users or change roles verify their signature (Svix, Standard Webhooks, HMAC) | S | High | A08 | CWE-345 |
| AUTHP-LINK-001 | Account linking requires verified email from every linked provider (no `allowDangerousEmailAccountLinking` without it; check `email_verified`) | S | High | A07 | CWE-287 |
| AUTHP-SECRET-001 | Provider secrets and session-signing secrets are server-only, loaded from the environment and strong (none hard-coded, none in public env vars) | S | High | A07 | CWE-798 |
| AUTHP-CALLBACK-001 | Callback and post-login redirect URLs are restricted (redirect callback checks origin; no wildcard callback URLs; `trustHost` only behind a trusted proxy) | S | Medium | A01 | CWE-601 |
| AUTHP-SESSION-001 | Session lifetime is appropriate and provider access/refresh tokens are not exposed to the browser through the client session | S | Medium | A07 | CWE-613 |
| AUTHP-SIGNUP-001 | Sign-up configuration matches intent: email verification required, invite-only/B2B apps restrict sign-up or allowed domains on the server | S | Medium | A07 | CWE-287 |
| AUTHP-ORG-001 | The active organization/tenant comes from the verified session (or membership is checked), never from a request parameter alone | S | High | A01 | CWE-639 |
| AUTHP-SYNC-001 | Users deleted, banned or removed from an org at the provider lose access in the app (webhook sync, session revocation, no stale local roles) | S | Medium | A07 | CWE-613 |
| AUTHP-CREDS-001 | Credentials providers (NextAuth Credentials, Better Auth email/password) verify password hashes, rate-limit, and return a generic failure | S | High | A07 | CWE-287 |
| AUTHP-MAINT-001 | Auth libraries and provider SDKs are maintained and current (no deprecated packages such as Lucia v3 or the Supabase auth-helpers) | S | Low | A06 | CWE-1104 |

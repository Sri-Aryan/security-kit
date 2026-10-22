# Auth provider integration guide

Sources: Clerk (Middleware, `auth()`, metadata types, webhooks via Svix, Organizations), Auth0 (Actions, `app_metadata`
vs `user_metadata`, Next.js SDK), Auth.js / NextAuth (callbacks, `allowDangerousEmailAccountLinking`, `trustHost`,
Credentials provider), Better Auth (email verification, account linking, trusted origins), Supabase Auth (`getUser` vs
`getSession` vs `getClaims`, SSR, `app_metadata`, auth hooks), Firebase Auth (ID tokens, custom claims), WorkOS, Kinde,
Cognito; OWASP Authentication and Session Management cheat sheets.

Using a provider moves password storage and MFA out of your code, but **your code still decides who the user is and
what they may do**. Most integration bugs are the app trusting something the user controls.

## Who is the user? (AUTHP-SERVER-001)

| Provider | Trust on the server | Do not trust |
|---|---|---|
| Clerk | `auth()` / `currentUser()` / `clerkClient.authenticateRequest()` | user ID from body/query; `unsafeMetadata` |
| Auth.js | `auth()` / `getServerSession()` | `useSession()` data sent back to the server |
| Supabase | `supabase.auth.getUser()` or `getClaims()` (verifies the JWT) | `getSession()` on the server (cookie not revalidated) |
| Firebase | `admin.auth().verifyIdToken(token)` | decoding the ID token without verifying |
| Auth0 | SDK `getSession()` / access-token verification with JWKS (`iss`, `aud`, `exp`) | `jwt-decode` output |
| Better Auth | `auth.api.getSession({ headers })` | client-side session object |

## Checks

- **AUTHP-ROLE-001**: grep for `role`, `plan`, `isAdmin`, `credits` and see where they are read from. Clerk:
  `publicMetadata` (read-only for the user) or `privateMetadata`; never `unsafeMetadata`. Supabase/Auth0: `app_metadata`.
  Firebase: custom claims set by the Admin SDK. Changes go through a server endpoint that checks an admin.
- **AUTHP-MW-001**: Clerk's `clerkMiddleware()` protects nothing until you call `auth.protect()` (for a matcher or for
  everything except public routes). A public-route list containing `/api(.*)` leaves every API route open unless each
  checks `auth()` itself. Prefer: protect everything, list public routes explicitly.
- **AUTHP-WEBHOOK-001**: user/org sync webhooks (`user.created`, `organizationMembership.created`, Auth0 Actions calling
  your API, Supabase auth hooks) must verify the signature over the **raw body** (Svix `Webhook.verify`, Standard
  Webhooks). See `/sk-webhooks` for replay and idempotency.
- **AUTHP-LINK-001**: linking OAuth accounts by email is safe only if every provider verifies email ownership. Check
  `email_verified` in OIDC profiles; avoid `allowDangerousEmailAccountLinking` unless all providers are trusted.
- **AUTHP-SECRET-001**: `AUTH_SECRET`/`NEXTAUTH_SECRET`/`BETTER_AUTH_SECRET` ≥ 32 random bytes from the environment;
  `CLERK_SECRET_KEY`, Auth0 client secret, WorkOS API key server-only. Publishable keys are fine in the client.
- **AUTHP-CALLBACK-001**: Auth.js `redirect` callback: allow relative URLs and `new URL(url).origin === baseUrl`
  only. Provider dashboards: exact callback URLs, no wildcards on production apps. `trustHost` only behind a proxy that
  sets Host (otherwise set `AUTH_URL`).
- **AUTHP-SESSION-001**: don't copy provider refresh tokens into the session callback (it reaches `useSession()`); keep
  JWT/session max age reasonable; revoke sessions on password change.
- **AUTHP-SIGNUP-001**: invite-only or B2B apps: disable public sign-up in the provider, or enforce allowed email
  domains on the server (not only in the UI). Require email verification before granting access.
- **AUTHP-ORG-001**: Clerk `auth().orgId` / `orgRole` / `has({ permission })`; WorkOS/PropelAuth org membership. A
  `?orgId=` parameter must be checked against membership before use.
- **AUTHP-SYNC-001**: handle `user.deleted` / banned / removed-from-org events; local role tables must not outlive
  provider removal.
- **AUTHP-CREDS-001**: Credentials `authorize()` must verify a hash (argon2/bcrypt), rate-limit (`/sk-ratelimit`), and
  return `null` on failure without revealing which part was wrong. See `/sk-password`.
- **AUTHP-MAINT-001**: Lucia v3 is deprecated (now a learning resource); `@supabase/auth-helpers-*` replaced by
  `@supabase/ssr`; `@clerk/clerk-sdk-node` replaced by `@clerk/express`. Plan migrations; check `/sk-deps` for advisories.

## Dynamic check (only with `--base-url`, test accounts the user owns)

Call protected API routes without a session and with user A's session against user B's org/object; tamper with
user-editable metadata from the client SDK and see whether the app treats it as a role.

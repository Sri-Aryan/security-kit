# Full-stack framework guide: where does this code run?

Sources: Next.js docs ("How to Think About Security in Next.js", Data Security, Authentication, Server Actions,
Middleware/Proxy, `server-only`, taint APIs), Next.js and React security advisories (CVE-2025-29927 middleware bypass,
CVE-2025-55182 React Server Components RCE and follow-ups), SvelteKit, Nuxt and Remix docs; OWASP cheat sheets.

## The boundary

| Code | Runs | Reachable by | Must |
|---|---|---|---|
| `'use server'` functions, SvelteKit `actions`, Remix `action` | server | **anyone**, via POST with any arguments | authenticate + authorize inside; validate args |
| `app/**/route.ts`, `pages/api/*`, `+server.ts`, `server/api/*` | server | anyone, any method/body | same |
| Server Components, `getServerSideProps`, `load`, `loader` | server | anyone who can request the page | check auth; return only needed fields |
| Props into a Client Component, `__NEXT_DATA__`, RSC payload | **sent to the browser** | the visitor | contain no secrets / other users' data |
| `middleware.ts` / `proxy.ts` | edge/server, before routing | — | treat as an optimistic redirect, not the security check |
| `NEXT_PUBLIC_*`, `VITE_*`, `PUBLIC_*`, `next.config` `env`, `define` | **inlined into client JS** | everyone | contain nothing secret |

Recommended pattern: a **data access layer** (`import 'server-only'`) whose functions take the session, check
authorization and return DTOs. Pages, actions and routes call it; nothing else touches the database.

## Checks

- **NEXT-ACTION-001/002**: In each action: `const session = await auth(); if (!session) throw …`; load the object
  and compare its owner/tenant with the session; parse arguments with zod/valibot (`schema.parse(input)`); ignore
  hidden form fields for user IDs, roles or prices. `next-safe-action`/`zsa` middleware is fine if every action uses it.
- **NEXT-ROUTE-001 / NEXT-SSR-001**: Same rule for handlers and loaders. Public endpoints are fine when intended:
  record them in the inventory as "public by design".
- **NEXT-MW-001/002**: CVE-2025-29927 (`x-middleware-subrequest`) skipped middleware entirely before 12.3.5 / 13.5.9 /
  14.2.25 / 15.2.3. Even when patched, middleware doesn't see Server Action authorization needs and matchers drift.
  Prefer `matcher` that covers everything except static assets, with an explicit public allow-list.
- **NEXT-VERSION-001**: Check `package.json` **and the lockfile**. For RSC (CVE-2025-55182, December 2025) upgrade to the
  latest patch of your line (later advisories added fixes), and rotate secrets if a vulnerable version was internet-facing.
- **NEXT-LEAK-001**: Look for `findUnique`/`findMany`/`select('*')` results passed whole into props or Client
  Components. Fix with `select: { … }`, a DTO mapper, or `experimental_taintObjectReference` / `taintUniqueValue` as
  a safety net.
- **NEXT-ENV-001 / NEXT-ONLY-001**: Anything secret must lack the public prefix and be used only in server modules
  marked `server-only` (SvelteKit: `$env/static/private`, `$lib/server`; Nuxt: non-public `runtimeConfig`). If a
  secret ever shipped, rotate it.
- **NEXT-IMAGE-001**: `images.remotePatterns` with exact hostnames; no `hostname: '**'`. With `dangerouslyAllowSVG`,
  also set `contentDispositionType: 'attachment'` and a `contentSecurityPolicy` with `script-src 'none'; sandbox;`.
- **NEXT-SOURCEMAP-001**: `productionBrowserSourceMaps: false`; Vite `build.sourcemap: 'hidden'` and upload to Sentry etc.
- **NEXT-CSRF-001**: Server Actions compare Origin with Host; behind proxies list exact `serverActions.allowedOrigins`.
  Custom cookie-auth route handlers need their own Origin/token check (see `/sk-csrf`).
- **NEXT-DRAFT-001 / NEXT-REVALIDATE-001**: Compare a server-side secret (constant-time) before `draftMode().enable()`
  or `revalidatePath/Tag`; never ship the secret to the client.

## Other frameworks

| Concept | SvelteKit | Nuxt | Remix / React Router |
|---|---|---|---|
| Mutations | `export const actions` in `+page.server.ts` | `server/api/*.post.ts` | `export async function action` |
| Loaders | `load` in `+page.server.ts` / `+layout.server.ts` (layout load doesn't re-run for every child!) | `server/api` + `useFetch` | `loader` |
| Auth context | `event.locals` set in `hooks.server.ts` | `event.context`, `getUserSession` | session storage in loader/action |
| Server-only | `$lib/server`, `$env/static/private` | non-public `runtimeConfig` | `.server.ts` modules |

## Dynamic check (only with `--base-url`, own environment)

Call a Server Action or route handler without cookies (copy the `Next-Action` header from a real request) and as a
second test user; expect 401/403. Fetch a page's `__NEXT_DATA__` / RSC payload and look for fields the UI doesn't show.

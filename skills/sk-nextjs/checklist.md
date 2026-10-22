# Full-stack framework checklist

Source of truth for `sk-nextjs` check IDs. Covers the server/client boundary of full-stack React-style frameworks:
Next.js (App Router and Pages Router) first, and the same concepts in SvelteKit, Nuxt, Remix / React Router and Astro.
These frameworks blur where code runs: a function marked `'use server'` is a public endpoint, props cross the network,
and middleware is not a security boundary. Based on the Next.js security guidance ("How to Think About Security in
Next.js", data-security and authentication guides), framework advisories and the OWASP cheat sheets.
`references/guide.md` explains each check.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| NEXT-ACTION-001 | Every Server Action / form action / Remix action authenticates the caller and authorizes the specific object inside the action | S+D | High | A01 | CWE-862 |
| NEXT-ACTION-002 | Action arguments and form fields are validated at runtime (schema), and owner/role/price values never come from the client | S | High | A01 | CWE-639 |
| NEXT-ROUTE-001 | Route handlers, API routes, `+server` endpoints and Nuxt server routes check auth themselves, independent of middleware | S+D | High | A01 | CWE-306 |
| NEXT-MW-001 | Middleware is not the only authorization layer: data access, pages, actions and routes re-check the session | S | High | A01 | CWE-285 |
| NEXT-MW-002 | The middleware matcher covers every protected path (match everything, allow-list public paths; API routes protected another way if excluded) | S | Medium | A01 | CWE-284 |
| NEXT-VERSION-001 | Framework and React Server Components packages are patched against known critical advisories (e.g. CVE-2025-29927, CVE-2025-55182 and follow-ups) | S | Critical | A06 | CWE-1395 |
| NEXT-LEAK-001 | Server Components, `getServerSideProps`, loaders and `load` functions pass only the fields the UI needs to the client (DTOs, `select`), never whole records | S | High | A01 | CWE-200 |
| NEXT-SSR-001 | Server data loaders for private pages check the session before fetching, and don't rely on the page being unlinked | S | Medium | A01 | CWE-862 |
| NEXT-ENV-001 | No secrets in public env variables (`NEXT_PUBLIC_`, `VITE_`, `PUBLIC_`, `NUXT_PUBLIC_`…), `next.config` `env`, Vite `define` or Nuxt public runtimeConfig | S | High | A05 | CWE-200 |
| NEXT-ONLY-001 | Server-only modules (DB clients, secrets, admin SDKs) are marked `import 'server-only'` / live under `$lib/server` so they cannot be bundled into the client | S | Low | A05 | CWE-200 |
| NEXT-IMAGE-001 | The image optimizer allows only known remote hosts, and SVG is served with a sandboxing CSP and attachment disposition if enabled | S | Medium | A05 | CWE-918 |
| NEXT-SOURCEMAP-001 | Production browser source maps are not published (hidden maps uploaded to the error tracker instead) | S | Low | A05 | CWE-540 |
| NEXT-CSRF-001 | Server Actions `allowedOrigins` lists exact hosts; cookie-authenticated route handlers that change state check Origin or a token | S | Medium | A01 | CWE-352 |
| NEXT-DRAFT-001 | Draft / preview mode is enabled only after checking a secret, and the secret is not in client code | S | Medium | A07 | CWE-306 |
| NEXT-REVALIDATE-001 | On-demand revalidation endpoints require a secret or an authenticated admin | S | Low | A04 | CWE-306 |
| NEXT-TEST-001 | Tests call Server Actions and route handlers directly without a session (and as another user) and assert they are refused | S | Low | A04 | CWE-1125 |

# Hosting platform guide

Sources: Vercel (Deployment Protection, Environment Variables, Cron Jobs, Spend Management, Headers), Netlify
(Environment variables, Site protection, `_headers`/`_redirects`, Proxy rewrites), Cloudflare Workers (Secrets,
`workers_dev`/`preview_urls`, Access), Render (Blueprint `envVars`, `sync: false`, database IP allow lists, private
services), Railway, Fly.io (Secrets, private networking/Flycast, `fly.toml` services), Heroku, Firebase Hosting / App
Hosting, DigitalOcean App Platform; OWASP cheat sheets.

## What lives where

| Platform | Config in repo | Secret store | Private networking |
|---|---|---|---|
| Vercel | `vercel.json` | Project env vars (per environment) | — (use Secure Compute / provider allow-lists) |
| Netlify | `netlify.toml`, `_headers`, `_redirects` | Site env vars (scopes, contexts) | — |
| Cloudflare | `wrangler.toml` / `wrangler.jsonc` | `wrangler secret put`, `.dev.vars` (git-ignored) | Service bindings, Access |
| Render | `render.yaml` | `sync: false`, env groups | Private services, `ipAllowList` |
| Fly.io | `fly.toml` | `fly secrets set` | 6PN `.internal`, Flycast |
| Railway | `railway.json` / `.toml` | Variables, shared variables | Private networking (`*.railway.internal`) |
| Heroku | `app.json`, `Procfile` | Config vars | Private Spaces |
| Firebase | `firebase.json`, `apphosting.yaml` | Secret Manager (`secret:` refs) | — |
| DigitalOcean | `.do/app.yaml` | `type: SECRET` | VPC, trusted sources |

## Checks

- **PAAS-SECRET-001**: values for SECRET/TOKEN/KEY/PASSWORD names committed in any of the files above. Public
  identifiers (publishable keys, analytics IDs) are fine. Rotate anything real that was committed, including in history.
- **PAAS-ENV-001 / PAAS-PREVIEW-001**: preview deployments run untrusted branch code (and on some setups, fork PRs).
  Give previews their own database and test-mode keys (Stripe test keys, sandbox email); enable Vercel Deployment
  Protection / Netlify password / Cloudflare Access on preview URLs. Ask the user what the dashboard shows; the repo
  rarely records it.
- **PAAS-EXPOSE-001**: `workers_dev = true` (and preview URLs) expose the Worker on `*.workers.dev`, skipping Access, WAF
  and rate limits on your routes. Fly `[[services]]` publishing 5432/6379/… exposes data stores on the public IP.
  Render "web services" are public; use "private services" for internal APIs.
- **PAAS-DB-001**: Render `ipAllowList` with `0.0.0.0/0`, DigitalOcean trusted sources missing, Railway TCP proxy on
  a database, Fly Postgres with a public IP. Prefer private networking.
- **PAAS-TLS-001**: `force_https = false` (Fly), HTTP-only custom domains; HSTS once HTTPS works everywhere.
- **PAAS-ROUTE-001**: destinations built from request parameters (`https://:host/...`, `$1` in the host) make an open
  proxy; destinations to `http://` or internal IPs publish internal services.
- **PAAS-CRON-001**: Vercel cron paths are visible in `vercel.json`. Check `request.headers.get('authorization') ===
  `Bearer ${process.env.CRON_SECRET}``. `x-vercel-cron` and the `vercel-cron` user agent can be forged.
- **PAAS-BUILD-001**: `printenv`/`env` in build commands put every secret in build logs; `publish = "."` or
  `"public": "."` serves the repository root.
- **PAAS-HEADERS-001**: headers may come from the framework (e.g. `next.config` `headers()`), the platform files, or a
  CDN; confirm with `curl -sI https://<site>` (only on the user's own site).
- **PAAS-ACCESS-001 / PAAS-SPEND-001**: dashboard settings: MFA/SSO for team members, scoped deploy tokens, spend
  limits/alerts, function max duration. Ask the user; record answers as evidence.

## Dynamic checks (only with `--base-url`, user's own deployment)

`curl -sI` the production and a preview URL (protection? headers? HTTPS redirect?), the `*.workers.dev` URL if
`workers_dev` is on, and each cron path without the secret (expect 401).

# Hosting platform checklist

Source of truth for `sk-paas` check IDs. Covers the platform configuration that ships next to the code of most indie
and small-team apps: Vercel (`vercel.json`), Netlify (`netlify.toml`, `_headers`, `_redirects`), Cloudflare Workers and
Pages (`wrangler.toml`/`wrangler.jsonc`), Render (`render.yaml`), Railway, Fly.io (`fly.toml`), Heroku (`app.json`,
`Procfile`), Firebase Hosting / App Hosting, DigitalOcean App Platform and Amplify Hosting. Infrastructure written as
Terraform/CloudFormation/Pulumi belongs to `/sk-cloud`. Based on each platform's security documentation and the OWASP
cheat sheets. `references/guide.md` explains each check.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| PAAS-SECRET-001 | No secret values committed in platform config (Wrangler `[vars]`, `render.yaml`/app spec `envVars`, `app.json`, `netlify.toml`, `fly.toml`); secrets live in the platform's secret store | S | Critical | A07 | CWE-798 |
| PAAS-ENV-001 | Secrets are scoped per environment: preview/branch deployments use separate, low-privilege keys and databases, not production ones | S | High | A05 | CWE-668 |
| PAAS-PREVIEW-001 | Preview and branch deployments are protected (deployment protection, password, SSO or Access) or contain no real data | S+D | High | A01 | CWE-284 |
| PAAS-EXPOSE-001 | Only intended services are public: no `workers.dev`/preview URLs bypassing edge protections, no databases or admin ports published as public services | S+D | High | A05 | CWE-284 |
| PAAS-DB-001 | Managed databases and caches accept connections only from the app (private networking or a narrow IP allow-list), never `0.0.0.0/0` | S | High | A05 | CWE-284 |
| PAAS-TLS-001 | HTTPS is forced on every public hostname | S+D | Medium | A02 | CWE-319 |
| PAAS-ROUTE-001 | Rewrites, redirects and proxies have fixed destinations: no request-controlled hosts (open proxy), no plain-HTTP or internal origins exposed publicly | S | High | A10 | CWE-441 |
| PAAS-CRON-001 | Scheduled endpoints verify a secret or signed request (`CRON_SECRET`, QStash, Cloud Scheduler OIDC), not a spoofable header | S | High | A01 | CWE-306 |
| PAAS-BUILD-001 | Builds don't print environment variables and publish only the build output (never the repository root, `.env` or source) | S | Medium | A05 | CWE-532 |
| PAAS-HEADERS-001 | Security headers (HSTS, CSP, frame-ancestors/X-Frame-Options, nosniff) are set at the platform edge or by the app | S+D | Low | A05 | CWE-693 |
| PAAS-ACCESS-001 | Team access to the hosting account is least-privilege with MFA, and deploy tokens are scoped and rotated | S | Medium | A07 | CWE-308 |
| PAAS-SPEND-001 | Usage-billed resources have spend limits or alerts and function duration/concurrency caps, so abuse cannot run up an unbounded bill | S | Low | A04 | CWE-770 |

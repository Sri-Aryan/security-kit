"""sk-paas rules: hosting-platform configuration (Vercel, Netlify, Cloudflare Workers/Pages, Render, Railway, Fly.io,
Heroku, Firebase Hosting / App Hosting, DigitalOcean App Platform, Amplify Hosting)."""

SKILL = "sk-paas"

# Path regexes (path_includes is not macro-expanded).
PLATFORM_FILE = (r"(?i)(^|/)(vercel\.json|netlify\.toml|wrangler\.(toml|jsonc?)|render\.ya?ml|fly\.toml|railway\.(json|toml)|"
                 r"app\.json|firebase\.json|apphosting\.ya?ml|\.do/app\.ya?ml|app\.ya?ml|amplify\.ya?ml|nixpacks\.toml|"
                 r"Procfile|_headers|_redirects)$")
WRANGLER = r"(?i)(^|/)wrangler\.(toml|jsonc?)$"

RULES = [
    # ------------------------------------------------------------------ SECRETS
    {
        "id": "paas-wrangler-secret-var", "check_id": "PAAS-SECRET-001", "title": "Secret committed as a plain Wrangler var", "files": [".toml", ".json", ".jsonc"],
        "path_includes": WRANGLER,
        "pattern": r"^\s*\"?{{SECRET_NAME}}\"?\s*[=:]\s*\"[^\"\s$]{6,}\"",
        "not_near": {"pattern": "{{PLACEHOLDER}}", "lines": 0}, "confidence": "HIGH", "redact": True,
        "note": "[vars] are committed and visible in the dashboard. Use `wrangler secret put` (and .dev.vars, git-ignored, for local).",
        "examples": {"match": [{"b64": "U1RSSVBFX1NFQ1JFVF9LRVkgPSAic2tfbGl2ZV81MVF6OHhSMm1ONHZCN2tMOXBXMyI="}],
                     "no_match": ["ENVIRONMENT = \"production\"", "API_TOKEN = \"${API_TOKEN}\""]},
    },
    {
        "id": "paas-config-secret-literal", "check_id": "PAAS-SECRET-001", "title": "Secret value committed in platform config", "files": ["config", "Procfile"],
        "path_includes": PLATFORM_FILE,
        "pattern": r"^\s*\"?{{SECRET_NAME}}\"?\s*[=:]\s*[\"']?[A-Za-z0-9_\-+/=.]{12,}[\"']?\s*,?\s*$",
        "not_near": {"pattern": "{{PLACEHOLDER}}|(?i:generateValue|fromDatabase|fromService|sync\\s*:\\s*false|\\$\\{\\{)", "lines": 0}, "confidence": "HIGH", "redact": True,
        "examples": {"match": [{"b64": "ICAiSldUX1NFQ1JFVCI6ICJhOGYzbjJrNHA5cTd6MXgwdjVjNiIs"}],
                     "no_match": ["  \"JWT_SECRET\": \"${JWT_SECRET}\",", "  \"NODE_ENV\": \"production\","]},
    },
    {
        "id": "paas-render-envvar-value", "check_id": "PAAS-SECRET-001", "title": "Secret value committed in render.yaml / app spec envVars", "files": ["config"],
        "path_includes": r"(?i)(^|/)(render\.ya?ml|\.do/app\.ya?ml|app\.ya?ml|apphosting\.ya?ml|amplify\.ya?ml)$",
        "multiline": True,
        "pattern": r"(?im)^\s*-?\s*(key|name|variable)\s*:\s*{{SECRET_NAME}}\s*\n\s*value\s*:\s*[\"']?(?!\$\{)[^\s\"'#]{8,}",
        "confidence": "HIGH", "redact": True,
        "note": "Use `sync: false` (Render), `type: SECRET` (DigitalOcean) or the platform's secret manager instead of a value.",
        "examples": {"match": [{"b64": "ZW52VmFyczoKICAtIGtleTogU1RSSVBFX1NFQ1JFVF9LRVkKICAgIHZhbHVlOiBza19saXZlX2FiY2RlZjEyMzQ1Ng=="}],
                     "no_match": ["envVars:\n  - key: STRIPE_SECRET_KEY\n    sync: false"]},
    },
    # ------------------------------------------------------------------ EXPOSURE
    {
        "id": "paas-workers-dev-on", "check_id": "PAAS-EXPOSE-001", "title": "Worker also reachable on *.workers.dev", "files": [".toml", ".json", ".jsonc"],
        "path_includes": WRANGLER,
        "pattern": r"^\s*\"?workers_dev\"?\s*[=:]\s*true", "confidence": "MEDIUM",
        "note": "The workers.dev URL bypasses Cloudflare Access, WAF and rate-limiting rules attached to your custom domain routes. Set workers_dev = false (and preview_urls = false) for production.",
        "examples": {"match": ["workers_dev = true"], "no_match": ["workers_dev = false"]},
    },
    {
        "id": "paas-fly-db-port-public", "check_id": "PAAS-EXPOSE-001", "title": "Database/admin port published as a Fly service", "files": [".toml"],
        "path_includes": r"(?i)(^|/)fly\.toml$",
        "pattern": r"^\s*internal_port\s*=\s*(5432|6379|3306|27017|9200|5601|2375|2376|8500|9090|11211|5984|7474|15672)\b",
        "near": {"pattern": r"\[\[services\]\]|\[http_service\]", "lines": 8}, "confidence": "MEDIUM",
        "note": "Publishing a data store on the public Anycast IP exposes it to the internet. Reach it over the private 6PN network (.internal / flycast) instead.",
        "examples": {"match": ["[[services]]\n  internal_port = 5432\n  protocol = \"tcp\""], "no_match": ["[http_service]\n  internal_port = 8080"]},
    },
    {
        "id": "paas-db-allow-all", "check_id": "PAAS-DB-001", "title": "Managed database open to every IP", "files": ["config"],
        "path_includes": PLATFORM_FILE,
        "multiline": True,
        "pattern": r"(?i)(ipAllowList|trusted_sources|allowed_ips|allowlist)[\s\S]{0,120}?0\.0\.0\.0/0", "confidence": "MEDIUM",
        "examples": {"match": ["databases:\n  - name: app-db\n    ipAllowList:\n      - source: 0.0.0.0/0\n        description: everywhere"],
                     "no_match": ["databases:\n  - name: app-db\n    ipAllowList: []"]},
    },
    {
        "id": "paas-https-not-forced", "check_id": "PAAS-TLS-001", "title": "HTTPS not forced", "files": ["config"],
        "path_includes": PLATFORM_FILE,
        "pattern": r"(?i)^\s*\"?force_?https\"?\s*[=:]\s*false|\"https_only\"\s*:\s*false|^\s*always_use_https\s*=\s*false", "confidence": "MEDIUM",
        "examples": {"match": ["  force_https = false"], "no_match": ["  force_https = true"]},
    },
    # ------------------------------------------------------------------ ROUTING
    {
        "id": "paas-open-proxy-rewrite", "check_id": "PAAS-ROUTE-001", "title": "Rewrite/redirect whose destination host comes from the request", "files": ["config", "_redirects", "js"],
        "pattern": r"\"destination\"\s*:\s*\"https?://(\$\d|:\w+)|^\s*/\S*\s+https?://:\w+|destination\s*:\s*['\"`]https?://(:\w+|\$\{)",
        "confidence": "HIGH", "note": "Lets anyone use your domain as an open proxy (phishing, cache poisoning, SSRF to internal hosts).",
        "examples": {"match": ["{ \"source\": \"/p/:host/:path*\", \"destination\": \"https://:host/:path*\" }", "/proxy/:host/*  https://:host/:splat  200"],
                     "no_match": ["{ \"source\": \"/api/:path*\", \"destination\": \"https://api.acme.com/:path*\" }"]},
    },
    {
        "id": "paas-rewrite-to-internal", "check_id": "PAAS-ROUTE-001", "title": "Public rewrite/proxy to an internal or plain-HTTP origin", "files": ["config", "_redirects", "js"],
        "pattern": r"(?i)(\"destination\"\s*:\s*|destination\s*:\s*|^\s*/\S*\s+)[\"'`]?http://(?!localhost\b)|(\"destination\"\s*:\s*|destination\s*:\s*|^\s*/\S*\s+)[\"'`]?https?://([\w-]+\.internal\b|[\w-]+\.local\b|10\.\d|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)",
        "confidence": "MEDIUM",
        "examples": {"match": ["{ \"source\": \"/admin/:path*\", \"destination\": \"http://10.0.0.5/:path*\" }"],
                     "no_match": ["{ \"source\": \"/api/:path*\", \"destination\": \"https://api.acme.com/:path*\" }"]},
    },
    # ------------------------------------------------------------------ CRON
    {
        "id": "paas-cron-route-no-secret", "check_id": "PAAS-CRON-001", "type": "absence", "scope": "file",
        "title": "Cron endpoint without a secret check", "files": ["js", "py"],
        "path_includes": r"(?i)(^|/)(app|pages|src|api|routes|functions|netlify)/.*cron",
        "when": r"export\s+(async\s+)?function\s+(GET|POST)\b|export\s+default|export\s+const\s+handler|^def\s+\w+\(|@\w+\.(get|post|route)\(",
        "missing": r"(?i)CRON_SECRET|authorization|verifySignature|upstash-signature|qstash|x-cloudscheduler|X-Appengine-Cron|OIDC|schedule\(",
        "confidence": "MEDIUM", "note": "Cron paths are listed in vercel.json and easy to guess. Compare the Authorization header to `Bearer ${CRON_SECRET}`.",
        "examples": {"match": ["export async function GET() {\n  await sendAllReminderEmails();\n  return Response.json({ ok: true });\n}"],
                     "no_match": ["export async function GET(req) {\n  if (req.headers.get('authorization') !== `Bearer ${process.env.CRON_SECRET}`) return new Response(null, { status: 401 });\n}"]},
    },
    {
        "id": "paas-cron-trusts-header", "check_id": "PAAS-CRON-001", "title": "Cron caller identified by a spoofable header", "files": ["js", "py"],
        "pattern": r"(?i)['\"]x-vercel-cron['\"]|user-?agent[^\n]*vercel-cron|['\"]x-netlify-cron['\"]", "confidence": "MEDIUM",
        "note": "Any client can send these headers. Use a shared secret (CRON_SECRET) or a signed request (QStash, Cloud Scheduler OIDC).",
        "examples": {"match": ["if (req.headers.get('x-vercel-cron')) await runJob();"], "no_match": ["if (auth === `Bearer ${process.env.CRON_SECRET}`) await runJob();"]},
    },
    # ------------------------------------------------------------------ BUILD
    {
        "id": "paas-build-prints-env", "check_id": "PAAS-BUILD-001", "title": "Build/deploy command prints environment variables", "files": ["config", "Procfile", "shell"],
        "pattern": r"(?i)(command|buildCommand|build_command|installCommand|preDeployCommand|startCommand|\"build\"|release|run)\s*[=:]\s*[\"'][^\"'\n]*(\bprintenv\b|\benv\s*($|[|&;>\"'])|\bset\s*($|[|&;>\"'])|echo\s+[\"']?\$\{?\w*(SECRET|TOKEN|KEY|PASS))",
        "confidence": "MEDIUM", "note": "Build logs are often visible to every team member and kept for weeks; on some platforms preview build logs are public.",
        "examples": {"match": ["  command = \"printenv && npm run build\""], "no_match": ["  command = \"npm run build\""]},
    },
    {
        "id": "paas-publish-repo-root", "check_id": "PAAS-BUILD-001", "title": "Repository root published as the static site", "files": ["config"],
        "path_includes": PLATFORM_FILE,
        "pattern": r"(?i)^\s*publish\s*=\s*[\"'](\.|\./|/)?[\"']|\"outputDirectory\"\s*:\s*\"(\.|\./)?\"|\"public\"\s*:\s*\"(\.|\./)?\"", "confidence": "MEDIUM",
        "note": "Serves source files, .env, .git leftovers and config to the internet. Publish the build output folder only.",
        "examples": {"match": ["[build]\n  publish = \".\"", "\"hosting\": { \"public\": \".\" }"], "no_match": ["[build]\n  publish = \"dist\""]},
    },
    # ------------------------------------------------------------------ HEADERS
    {
        "id": "paas-no-security-headers", "check_id": "PAAS-HEADERS-001", "type": "absence", "scope": "project",
        "title": "Static/edge-hosted site with no security headers configured anywhere", "files": ["config", "js", "_headers"],
        "when": r"\"(rewrites|redirects|cleanUrls|trailingSlash|outputDirectory)\"\s*:|^\s*\[build\]|\[\[redirects\]\]|\"hosting\"\s*:",
        "missing": r"(?i)Strict-Transport-Security|Content-Security-Policy|X-Frame-Options|frame-ancestors|X-Content-Type-Options|helmet\(|securityHeaders",
        "confidence": "LOW", "note": "Headers may come from the framework, a CDN or a proxy; confirm with a request to the live site.",
        "examples": {"match": ["{ \"rewrites\": [{ \"source\": \"/(.*)\", \"destination\": \"/\" }] }"],
                     "no_match": ["{ \"headers\": [{ \"source\": \"/(.*)\", \"headers\": [{ \"key\": \"X-Frame-Options\", \"value\": \"DENY\" }] }], \"rewrites\": [] }"]},
    },
]

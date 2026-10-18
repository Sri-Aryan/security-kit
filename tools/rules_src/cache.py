"""sk-cache rules: public caching of personal responses, unkeyed headers, extension-based cache rules, app caches."""

SKILL = "sk-cache"

MACROS = {
    "USER_CTX": r"(?i:req\.user|request\.user|current_user|currentUser|getServerSession|auth\(\)|cookies\(\)|session|/me\b|account|profile|dashboard|@login_required|\[Authorize\]|isAuthenticated)",
}

RULES = [
    # ------------------------------------------------------------------ PRIVATE
    {
        "id": "cache-public-personal", "check_id": "CACHE-PRIVATE-001", "title": "Public/shared caching on a user-specific response", "files": ["code", "config"],
        "pattern": r"(?i)Cache-Control['\"]?\s*[,:=]\s*['\"][^'\"]*\b(public|s-maxage)|cache_control\(\s*[^)]*public\s*=\s*True|patch_cache_control\([^)]*public\s*=\s*True|CacheControl\.maxAge\([^)]*\)\.cachePublic\(\)|\[ResponseCache\([^\]]*Location\s*=\s*ResponseCacheLocation\.(Any|Client)|expires_in\([^)]*public:\s*true",
        "near": {"pattern": "{{USER_CTX}}", "lines": 6}, "confidence": "MEDIUM",
        "examples": {"match": ["router.get('/me', requireAuth, (req, res) => {\n  res.set('Cache-Control', 'public, max-age=300');\n  res.json(req.user);\n});"],
                     "no_match": ["router.get('/me', requireAuth, (req, res) => {\n  res.set('Cache-Control', 'private, no-store');\n  res.json(req.user);\n});"]},
    },
    {
        "id": "cache-page-cache-on-auth", "check_id": "CACHE-PRIVATE-001", "title": "Page/output cache applied to an authenticated view", "files": ["py", "cs", "rb", "java"],
        "pattern": r"@cache_page\(|@method_decorator\(\s*cache_page|\[OutputCache\b|caches_page\s+:|@Cacheable\(",
        "near": {"pattern": r"@login_required|LoginRequiredMixin|request\.user|\[Authorize\]|before_action\s+:authenticate|current_user|@PreAuthorize|SecurityContextHolder", "lines": 6},
        "not_near": {"pattern": r"(?i)vary_on_cookie|vary_on_headers|VaryByHeader|key\s*=\s*['\"][^'\"]*#\w*user|cache_key.*user", "lines": 4},
        "confidence": "HIGH", "note": "The first user's page is served to everyone until the cache expires.",
        "examples": {"match": ["@login_required\n@cache_page(60 * 15)\ndef dashboard(request):"], "no_match": ["@cache_page(60 * 15)\ndef pricing(request):"]},
    },
    {
        "id": "cache-next-static-auth", "check_id": "CACHE-PRIVATE-001", "title": "Next.js route cached statically while reading the session", "files": ["js"],
        "pattern": r"export\s+const\s+(revalidate\s*=\s*\d+|dynamic\s*=\s*['\"]force-static['\"])|unstable_cache\(|['\"]use cache['\"]",
        "file_requires": r"cookies\(\)|getServerSession|\bauth\(\)|headers\(\)|currentUser\(|getSession\(", "confidence": "MEDIUM",
        "examples": {"match": ["import { cookies } from 'next/headers';\nexport const revalidate = 3600;\nexport default async function Page() { const s = cookies().get('session'); }"],
                     "no_match": ["export const revalidate = 3600;\nexport default async function Pricing() { return <Plans />; }"]},
    },
    # ------------------------------------------------------------------ UNKEYED
    {
        "id": "cache-unkeyed-header", "check_id": "CACHE-UNKEYED-001", "title": "Unkeyed forwarding header read by the application", "files": ["code"],
        "pattern": r"(?i)(headers?\s*(\[|\.get\(|\.)\s*['\"]?|getHeader\(\s*['\"]|Request\.Headers\[\s*['\"]|HTTP_)(x[-_]forwarded[-_]host|x[-_]original[-_]url|x[-_]rewrite[-_]url|x[-_]forwarded[-_]scheme|x[-_]forwarded[-_]server|x[-_]host|x[-_]forwarded[-_]prefix|x[-_]http[-_]method[-_]override)",
        "confidence": "MEDIUM", "note": "If this value reaches a cached response (links, redirects, script URLs), one request poisons the cache for everyone.",
        "examples": {"match": ["const base = `https://${req.headers['x-forwarded-host']}`;", "host = request.headers.get('X-Forwarded-Host')"],
                     "no_match": ["const base = process.env.PUBLIC_URL;"]},
    },
    # ------------------------------------------------------------------ DECEPTION
    {
        "id": "cache-by-extension", "check_id": "CACHE-DECEPTION-001", "title": "Cache rule keyed on file extension", "files": ["config", "code"],
        "pattern": r"location\s+~\*?\s+[^{]*\\\.\(?(css|js|png|jpe?g|gif|ico|svg|woff2?|webp)|path_pattern\s*=\s*['\"]\*\.(css|js|png|jpe?g|gif|svg)['\"]|PathPattern\s*:\s*['\"]?\*\.(css|js|png|jpe?g)|\"(cache_everything|cacheEverything)\"\s*:\s*true|cache_level\s*=\s*['\"]cache_everything['\"]",
        "near": {"pattern": r"(?i)proxy_cache|expires|Cache-Control|cache_policy|CachePolicy|default_ttl|cache_everything|edge_ttl", "lines": 6},
        "confidence": "LOW", "note": "Check the origin returns 404 (not the page) for /account/x.css and similar paths, or cache only paths under a static prefix.",
        "examples": {"match": ["location ~* \\.(css|js|png)$ {\n  proxy_cache static;\n  proxy_pass http://app;\n}"], "no_match": ["location /static/ {\n  proxy_cache static;\n  root /srv/static;\n}"]},
    },
    # ------------------------------------------------------------------ APP
    {
        "id": "cache-app-constant-key", "check_id": "CACHE-APP-001", "title": "Application cache stores personal data under a constant key", "files": ["code"],
        "pattern": r"(?i)\b\w*(cache|redis|memcache|lru|store)\w*\.(set|get|setex|put|remember|fetch|getOrSet|wrap)\(\s*['\"](?![^'\"]*(\$\{|%s|\{\}|#\{))[^'\"]*\b(profile|account|dashboard|orders|cart|me|settings|inbox|notifications|balance|user)\b[^'\"]*['\"]\s*[,)]",
        "confidence": "MEDIUM",
        "examples": {"match": ["const data = await cache.wrap('dashboard', () => loadDashboard(req.user.id));"],
                     "no_match": ["const data = await cache.wrap(`dashboard:${req.user.id}`, () => loadDashboard(req.user.id));"]},
    },
    # ------------------------------------------------------------------ SENSITIVE
    {
        "id": "cache-sensitive-no-store", "check_id": "CACHE-SENSITIVE-001", "type": "absence", "scope": "project",
        "title": "No `no-store` anywhere for authenticated or sensitive responses", "files": ["code", "config"],
        "when": r"(?i)(login|signin|account|checkout|payment|/me\b|profile|token)['\"`]",
        "file_requires": r"(?i)(app|router|server)\.(get|post)\(|@(app|router)\.(get|post)|@(Get|Post)Mapping|\bpath\(|Route::",
        "missing": r"(?i)no-store|nocache\(|never_cache|cache_control\([^)]*no_store|NoStore\s*=\s*true|private,\s*no-cache|helmet\.noCache",
        "confidence": "LOW",
        "examples": {"match": ["router.get('/account', requireAuth, showAccount);"], "no_match": ["router.get('/account', requireAuth, (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); }, showAccount);"]},
    },
    # ------------------------------------------------------------------ PURGE
    {
        "id": "cache-purge-endpoint", "check_id": "CACHE-PURGE-001", "title": "Cache purge/flush endpoint without visible authorization", "files": ["code"],
        "pattern": r"(?i)(\.(get|post|delete|all)\(|@(app|router)\.(get|post|delete)\(|@(Get|Post|Delete)Mapping\(|Route::(get|post|delete)\()\s*['\"`][^'\"`]*/(purge|invalidate|clear[-_]?cache|flush|cache/clear|revalidate)\b",
        "not_near": {"pattern": r"(?i)(requireAuth|requireAdmin|isAdmin|authenticate|authorize|@PreAuthorize|admin_required|secret|token|signature|REVALIDATE_SECRET)", "lines": 4},
        "confidence": "MEDIUM",
        "examples": {"match": ["router.post('/cache/purge', async (req, res) => { await cdn.purgeAll(); res.end(); });"],
                     "no_match": ["router.post('/cache/purge', requireAdmin, async (req, res) => { await cdn.purgeAll(); res.end(); });"]},
    },
    # ------------------------------------------------------------------ ERROR
    {
        "id": "cache-errors-cached", "check_id": "CACHE-ERROR-001", "title": "Error responses cached by the proxy", "files": ["config"],
        "pattern": r"proxy_cache_valid\s+(any|[45]\d\d)\b|fastcgi_cache_valid\s+(any|[45]\d\d)\b|beresp\.status\s*(>=|==)\s*[45]\d\d[^\n]*beresp\.ttl\s*=|\"?error_caching_min_ttl\"?\s*[:=]\s*[1-9]\d{2,}",
        "confidence": "LOW",
        "examples": {"match": ["proxy_cache_valid any 10m;"], "no_match": ["proxy_cache_valid 200 302 10m;"]},
    },
]

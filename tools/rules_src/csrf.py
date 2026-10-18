"""sk-csrf rules: disabled protection, state-changing GETs, SameSite=None, CORS+credentials, token handling."""

SKILL = "sk-csrf"

MACROS = {
    "STATE_VERB": r"(?:delete|remove|destroy|logout|log-out|signout|sign-out|transfer|approve|reject|cancel|confirm|update|save|toggle|promote|demote|grant|revoke|reset|disable|enable|activate|deactivate|unsubscribe|invite|purchase|pay|withdraw)",
}

RULES = [
    # ------------------------------------------------------------------ DISABLED
    {
        "id": "csrf-protection-disabled", "check_id": "CSRF-DISABLED-001", "title": "CSRF protection disabled or exempted", "files": ["code", "config"],
        "pattern": r"csrf\(\s*\)\s*\.\s*disable\(\)|csrf\(\s*AbstractHttpConfigurer::disable\s*\)|csrf\(\s*\w+\s*->\s*\w+\.disable\(\)\s*\)|@csrf_exempt\b|\bcsrf_exempt\(|skip_forgery_protection|skip_before_action\s+:verify_authenticity_token|protect_from_forgery\s+with:\s*:null_session|\[IgnoreAntiforgeryToken\]|WTF_CSRF_ENABLED\s*=\s*False|WTF_CSRF_CHECK_DEFAULT\s*=\s*False|\bcsrf\s*:\s*false\b|csrfProtection\s*:\s*false|protected\s+\$except\s*=\s*\[\s*['\"][^'\"]+",
        "confidence": "MEDIUM", "note": "Fine for endpoints that don't use cookie auth (token-auth APIs, signed webhooks); check each.",
        "examples": {"match": ["http.csrf(csrf -> csrf.disable());", "@csrf_exempt\ndef transfer(request):", "skip_before_action :verify_authenticity_token"],
                     "no_match": ["http.csrf(Customizer.withDefaults());"]},
    },
    {
        "id": "csrf-no-protection", "check_id": "CSRF-TOKEN-001", "type": "absence", "scope": "project",
        "title": "Cookie sessions used but no CSRF defence found anywhere", "files": ["code"],
        "when": r"express-session|\bsession\(\s*\{|cookie-session|req\.session\b|@fastify/session|SessionMiddleware|iron-session|cookies\(\)\.set\(|res\.cookie\(\s*['\"](session|sid|token|auth|jwt)",
        "missing": r"(?i)(csrf|xsrf|csurf|lusca|tiny-csrf|doubleCsrf|Antiforgery|ValidateAntiForgeryToken|protect_from_forgery|CsrfViewMiddleware|CSRFProtect|sameSite\s*:\s*['\"]?(strict|lax)|SameSite=(Strict|Lax)|sec-fetch-site|req\.headers\.origin|headers\.get\(\s*['\"]origin)",
        "confidence": "MEDIUM",
        "examples": {"match": ["app.use(session({ secret: s, resave: false }));\napp.post('/transfer', handler);"],
                     "no_match": ["app.use(session({ secret: s, cookie: { sameSite: 'strict' } }));\napp.post('/transfer', handler);"]},
    },
    # ------------------------------------------------------------------ GET
    {
        "id": "csrf-state-change-on-get", "check_id": "CSRF-GET-001", "title": "State-changing action exposed on GET", "files": ["code"],
        "pattern": r"(?i)(\b(app|router|server|r|e|g|api)\.get\(|@(app|router|bp|blueprint)\.get\(|@GetMapping\(|Route::get\(|\bget\s+['\"]|MapGet\(|\.GET\()\s*(value\s*=\s*)?['\"`][^'\"`]*[/_-]{{STATE_VERB}}\b",
        "confidence": "MEDIUM", "note": "Links, images and prefetchers trigger GETs cross-site. Use POST/DELETE with CSRF protection.",
        "examples": {"match": ["router.get('/account/delete', requireAuth, deleteAccount);", "@app.get('/users/{id}/promote')", "Route::get('/logout', [AuthController::class, 'logout']);"],
                     "no_match": ["router.post('/account/delete', requireAuth, deleteAccount);", "router.get('/users/:id', show);"]},
    },
    # ------------------------------------------------------------------ COOKIE
    {
        "id": "csrf-samesite-none", "check_id": "CSRF-COOKIE-001", "title": "Session cookie with SameSite=None", "files": ["code", "config"],
        "pattern": r"(?i)sameSite\s*:\s*['\"]?none\b|SameSite=None|samesite\s*=\s*['\"]?none['\"]?|SameSiteMode\.None|SESSION_COOKIE_SAMESITE\s*=\s*(None|['\"]None['\"])|same_site:\s*:none",
        "confidence": "MEDIUM", "note": "Cookies are sent on cross-site requests; CSRF tokens become mandatory.",
        "examples": {"match": ["app.use(session({ cookie: { sameSite: 'none', secure: true } }));", "SESSION_COOKIE_SAMESITE = None"],
                     "no_match": ["app.use(session({ cookie: { sameSite: 'lax', secure: true } }));"]},
    },
    # ------------------------------------------------------------------ CORS
    {
        "id": "csrf-cors-credentials-any-origin", "check_id": "CSRF-CORS-001", "title": "CORS allows credentials for any or reflected origin", "files": ["code", "config"],
        "pattern": r"(?i)origin\s*:\s*(true|['\"]\*['\"]|\(\s*\w+\s*,\s*(cb|callback)\s*\)\s*=>\s*(cb|callback)\(\s*null\s*,\s*true\s*\))|Access-Control-Allow-Origin['\"]?\s*,\s*(req\.headers\.origin|request\.headers\[?['\"]?origin|origin\b)|allow_origin_regex\s*=\s*['\"]\.\*|allow_origins\s*=\s*\[\s*['\"]\*['\"]|AllowAnyOrigin\(\)|SetIsOriginAllowed\(\s*\w+\s*=>\s*true\s*\)|allowedOriginPatterns\(\s*\"\*\"\s*\)|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|CORS_ALLOW_ALL_ORIGINS\s*=\s*True",
        "near": {"pattern": r"(?i)credentials\s*:\s*true|Allow-Credentials|allow_credentials\s*=\s*True|AllowCredentials\(\)|allowCredentials\(\s*true|CORS_ALLOW_CREDENTIALS\s*=\s*True|supports_credentials\s*=\s*True", "lines": 5},
        "confidence": "HIGH",
        "examples": {"match": ["app.use(cors({ origin: true, credentials: true }));", "app.add_middleware(CORSMiddleware, allow_origin_regex='.*', allow_credentials=True)"],
                     "no_match": ["app.use(cors({ origin: ['https://app.example.com'], credentials: true }));"]},
    },
    # ------------------------------------------------------------------ JSON
    {
        "id": "csrf-json-accepts-any-type", "check_id": "CSRF-JSON-001", "title": "JSON parser accepts any or text/plain content type", "files": ["code"],
        "pattern": r"(express|bodyParser)\.json\(\s*\{[^}]*type\s*:\s*(['\"](\*/\*|text/plain|\*)['\"]|\(\s*\)\s*=>\s*true|\[[^\]]*text/plain)|force\s*=\s*True[^\n]*get_json|get_json\(\s*force\s*=\s*True",
        "confidence": "MEDIUM", "note": "A cross-site HTML form can post text/plain bodies that parse as JSON.",
        "examples": {"match": ["app.use(express.json({ type: '*/*' }));", "data = request.get_json(force=True)"], "no_match": ["app.use(express.json());"]},
    },
    # ------------------------------------------------------------------ TOKEN
    {
        "id": "csrf-token-in-url", "check_id": "CSRF-TOKEN-002", "title": "CSRF token placed in a URL", "files": ["code", "web"],
        "pattern": r"(?i)['\"`][^'\"`\s]*[?&](csrf|_csrf|csrf_?token|csrfmiddlewaretoken|authenticity_token|xsrf|_token)=",
        "confidence": "MEDIUM", "note": "URLs leak through logs, history and Referer. Send tokens in a header or form body.",
        "examples": {"match": ["fetch(`/api/delete?csrf_token=${token}`, { method: 'POST' });"], "no_match": ["fetch('/api/delete', { method: 'POST', headers: { 'X-CSRF-Token': token } });"]},
    },
    {
        "id": "csrf-token-weak-compare", "check_id": "CSRF-TOKEN-002", "title": "CSRF token compared with == or derived weakly", "files": ["code"],
        "pattern": r"(?i)\b\w*csrf\w*\s*(===?|!==?)\s*\w*|\w*\s*(===?|!==?)\s*\w*csrf\w*\b|\w*csrf\w*\s*=\s*[^\n]*({{WEAK_RANDOM}}|Date\.now\(\)|time\(\)|md5\(\s*\w*session)",
        "not_near": {"pattern": r"timingSafeEqual|compare_digest|hmac\.Equal|ConstantTimeCompare|hash_equals|secure_compare|FixedTimeEquals", "lines": 2}, "confidence": "LOW",
        "examples": {"match": ["if (req.body._csrf !== req.session.csrfToken) return res.sendStatus(403);"],
                     "no_match": ["if (!crypto.timingSafeEqual(Buffer.from(req.body._csrf), Buffer.from(req.session.csrfToken))) return res.sendStatus(403);"]},
    },
]

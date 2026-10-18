"""sk-browser rules: headers, framing, cookie flags, browser storage, bundle secrets, SRI, third parties."""

SKILL = "sk-browser"

MACROS = {
    "WEB_SERVER": r"\bexpress\(\s*\)|\bfastify\(|new\s+Koa\(|FastAPI\(|Flask\(__name__|django|SpringApplication|WebApplication\.CreateBuilder|gin\.(Default|New)\(|echo\.New\(|http\.ListenAndServe|Rails\.application|Laravel|createServer\(|next\.config|nuxt\.config|server\s*\{",
    "AUTH_COOKIE": r"(?i:session|sid|token|auth|jwt|refresh|remember|access)",
}

RULES = [
    # ------------------------------------------------------------------ HEADERS / FRAME
    {
        "id": "browser-no-security-headers", "check_id": "BROWSER-HEADERS-001", "type": "absence", "scope": "project",
        "title": "Web server code but no security headers configured anywhere", "files": ["code", "config"],
        "when": "{{WEB_SERVER}}",
        "missing": r"(?i)(helmet|Strict-Transport-Security|X-Content-Type-Options|secure_headers|SecureHeaders|django\.middleware\.security|SECURE_HSTS_SECONDS|UseHsts|add_header\s+Strict-Transport|talisman|secure-headers|async\s+headers\(\)|headers\s*:\s*\[\s*\{|\.headers\(\s*headers\s*->|hsts\()",
        "confidence": "MEDIUM", "note": "Headers may be added by a proxy or CDN; ask the user or check with --base-url before reporting.",
        "examples": {"match": ["const app = express();\napp.get('/', home);"], "no_match": ["const app = express();\napp.use(helmet());"]},
    },
    {
        "id": "browser-no-frame-protection", "check_id": "BROWSER-FRAME-001", "type": "absence", "scope": "project",
        "title": "No clickjacking protection (frame-ancestors / X-Frame-Options) found", "files": ["code", "config"],
        "when": "{{WEB_SERVER}}",
        "missing": r"(?i)(frame-ancestors|frameAncestors|X-Frame-Options|frameguard|helmet|xframe|XFrameOptionsMiddleware|X_FRAME_OPTIONS|frameOptions)",
        "confidence": "MEDIUM",
        "examples": {"match": ["app = FastAPI()\n@app.get('/')\ndef home(): ..."], "no_match": ["app = FastAPI()\n# middleware sets X-Frame-Options: DENY"]},
    },
    {
        "id": "browser-hsts-short", "check_id": "BROWSER-HEADERS-001", "title": "HSTS max-age shorter than about 4 months", "files": ["code", "config"],
        "pattern": r"(?i)Strict-Transport-Security[^\n]*max-age=\d{1,7}\b|SECURE_HSTS_SECONDS\s*=\s*\d{1,7}\b|hsts\s*:\s*\{[^}]*maxAge\s*:\s*\d{1,7}\b|MaxAge\s*=\s*TimeSpan\.FromDays\(\s*\d{1,2}\s*\)",
        "confidence": "LOW", "note": "Use max-age=31536000 (1 year) with includeSubDomains once HTTPS is everywhere.",
        "examples": {"match": ["res.setHeader('Strict-Transport-Security', 'max-age=3600');", "SECURE_HSTS_SECONDS = 60"],
                     "no_match": ["res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');"]},
    },
    {
        "id": "browser-referrer-unsafe", "check_id": "BROWSER-HEADERS-001", "title": "Referrer-Policy leaks full URLs cross-origin", "files": ["code", "config", "web"],
        "pattern": r"(?i)Referrer-Policy['\"]?\s*[:,]\s*['\"]?unsafe-url|referrerPolicy\s*[:=]\s*\{?\s*(policy\s*:\s*)?['\"](unsafe-url)['\"]|<meta\s+name=['\"]referrer['\"]\s+content=['\"]unsafe-url",
        "confidence": "LOW",
        "examples": {"match": ["res.setHeader('Referrer-Policy', 'unsafe-url');"], "no_match": ["res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');"]},
    },
    # ------------------------------------------------------------------ COOKIE
    {
        "id": "browser-cookie-flags-off", "check_id": "BROWSER-COOKIE-001", "title": "Cookie Secure/HttpOnly explicitly disabled", "files": ["code", "config"],
        "pattern": r"(?i)\bhttp_?only\s*[:=]\s*false|\bsecure\s*:\s*false|SESSION_COOKIE_(SECURE|HTTPONLY)\s*=\s*False|CSRF_COOKIE_SECURE\s*=\s*False|setHttpOnly\(\s*false\s*\)|setSecure\(\s*false\s*\)|HttpOnly\s*=\s*false|Secure\s*=\s*false|server\.servlet\.session\.cookie\.(secure|http-only)\s*=\s*false|session\.cookie_(secure|httponly)\s*=\s*(0|Off|false)",
        "near": {"pattern": r"(?i)cookie|session", "lines": 4}, "path_excludes": r"(?i)(dev|local|test)", "confidence": "HIGH",
        "examples": {"match": ["app.use(session({ cookie: { secure: false, httpOnly: false } }));", "SESSION_COOKIE_SECURE = False"],
                     "no_match": ["app.use(session({ cookie: { secure: true, httpOnly: true, sameSite: 'lax' } }));"]},
    },
    {
        "id": "browser-auth-cookie-no-options", "check_id": "BROWSER-COOKIE-001", "title": "Auth cookie set without options (defaults are not HttpOnly/Secure)", "files": ["code"],
        "pattern": r"res\.cookie\(\s*['\"`][^'\"`]*{{AUTH_COOKIE}}[^'\"`]*['\"`]\s*,\s*[^,()]+(\([^()]*\))?\s*\)|set_cookie\(\s*['\"][^'\"]*{{AUTH_COOKIE}}[^'\"]*['\"]\s*,\s*[^,()]+\)|cookies\(\)\.set\(\s*['\"][^'\"]*{{AUTH_COOKIE}}[^'\"]*['\"]\s*,\s*[^,()]+\)",
        "confidence": "MEDIUM",
        "examples": {"match": ["res.cookie('session', token);", "response.set_cookie('auth_token', token)"],
                     "no_match": ["res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' });"]},
    },
    {
        "id": "browser-auth-cookie-from-js", "check_id": "BROWSER-COOKIE-001", "title": "Auth cookie written from JavaScript (cannot be HttpOnly)", "files": ["js", "web"],
        "pattern": r"document\.cookie\s*=\s*[^;\n]*{{AUTH_COOKIE}}|Cookies\.set\(\s*['\"][^'\"]*{{AUTH_COOKIE}}|setCookie\(\s*['\"][^'\"]*{{AUTH_COOKIE}}",
        "confidence": "MEDIUM",
        "examples": {"match": ["document.cookie = `token=${jwt}; path=/`;", "Cookies.set('access_token', t);"], "no_match": ["document.cookie = 'theme=dark; path=/';"]},
    },
    # ------------------------------------------------------------------ STORAGE / BUNDLE
    {
        "id": "browser-token-in-storage", "check_id": "BROWSER-STORAGE-001", "title": "Token or secret stored in localStorage/sessionStorage", "files": ["js", "web"],
        "pattern": r"(?i)(localStorage|sessionStorage)\.setItem\(\s*['\"`][^'\"`]*(token|jwt|auth|session|secret|api_?key|apikey|refresh|credential|password)[^'\"`]*['\"`]|(localStorage|sessionStorage)\s*\[\s*['\"`][^'\"`]*(token|jwt|auth|secret)[^'\"`]*['\"`]\s*\]\s*=",
        "confidence": "MEDIUM", "note": "Any XSS or third-party script can read it. Prefer HttpOnly cookies for session tokens.",
        "examples": {"match": ["localStorage.setItem('accessToken', data.token);"], "no_match": ["localStorage.setItem('sidebarCollapsed', 'true');"]},
    },
    {
        "id": "browser-secret-public-env", "check_id": "BROWSER-BUNDLE-001", "title": "Secret placed in a client-exposed environment variable", "files": ["code", "web", "env", "config"],
        "pattern": r"\b(NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY|PUBLIC|VUE_APP|STORYBOOK)_\w*(SECRET|PRIVATE|PASSWORD|PASSWD|SERVICE_ROLE|SERVICE_KEY|ADMIN_KEY|ADMIN_TOKEN|MASTER_KEY|SK_LIVE|DATABASE_URL|DB_URL)\w*",
        "confidence": "HIGH", "note": "These prefixes are compiled into the JavaScript every visitor downloads.",
        "examples": {"match": ["const s = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;", "VITE_SUPABASE_SERVICE_ROLE_KEY=placeholder"],
                     "no_match": ["const k = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;", "VITE_SUPABASE_ANON_KEY=placeholder"]},
    },
    # ------------------------------------------------------------------ SRI / 3P
    {
        "id": "browser-cdn-script-no-sri", "check_id": "BROWSER-SRI-001", "title": "Third-party script/stylesheet without Subresource Integrity", "files": ["web"],
        "pattern": r"<script\b(?![^>]*\bintegrity=)[^>]*\bsrc=['\"]https?://(?!localhost|127\.0\.0\.1|www\.googletagmanager\.com|js\.stripe\.com|www\.google\.com/recaptcha|challenges\.cloudflare\.com)[^'\"]+['\"](?![^>]*\bintegrity=)[^>]*>|<link\b(?=[^>]*rel=['\"]stylesheet['\"])(?![^>]*\bintegrity=)[^>]*\bhref=['\"]https?://(?!fonts\.googleapis\.com|localhost)[^'\"]+['\"](?![^>]*\bintegrity=)[^>]*>",
        "confidence": "LOW", "note": "Some providers (payment, captcha, tag managers) change scripts by design and can't use SRI; review those as trusted third parties instead.",
        "examples": {"match": ["<script src=\"https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js\"></script>"],
                     "no_match": ["<script src=\"https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js\" integrity=\"sha384-abc\" crossorigin=\"anonymous\"></script>"]},
    },
    {
        "id": "browser-tag-manager", "check_id": "BROWSER-THIRDPARTY-001", "title": "Tag manager can inject arbitrary scripts", "files": ["web", "js"],
        "pattern": r"googletagmanager\.com/gtm\.js|['\"]GTM-[A-Z0-9]{4,}['\"]|tags\.tiqcdn\.com|assets\.adobedtm\.com|cdn\.segment\.com/analytics\.js",
        "confidence": "LOW", "note": "Whoever controls the container can run code on every page. Restrict publishing rights and keep it off login/payment pages.",
        "examples": {"match": ["<script src=\"https://www.googletagmanager.com/gtm.js?id=GTM-ABC123\"></script>"], "no_match": ["<script src=\"/static/app.js\"></script>"]},
    },
    # ------------------------------------------------------------------ MIXED / TARGET
    {
        "id": "browser-mixed-content", "check_id": "BROWSER-MIXED-001", "title": "Subresource or form loaded over plain HTTP", "files": ["web"],
        "pattern": r"(<(script|img|iframe|audio|video|source|embed|object)\b[^>]*\bsrc|<link\b[^>]*\bhref|<form\b[^>]*\baction)=['\"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])",
        "confidence": "LOW",
        "examples": {"match": ["<img src=\"http://images.example.com/logo.png\">", "<form action=\"http://pay.example.com/submit\" method=\"post\">"],
                     "no_match": ["<img src=\"https://images.example.com/logo.png\">"]},
    },
    {
        "id": "browser-target-blank", "check_id": "BROWSER-TARGET-001", "title": "target=_blank link without rel=noopener", "files": ["web"],
        "pattern": r"<a\b(?![^>]*\brel=['\"][^'\"]*noopener)[^>]*\btarget=['\"]_blank['\"](?![^>]*\brel=['\"][^'\"]*noopener)[^>]*>",
        "confidence": "LOW", "note": "Modern browsers imply noopener; older ones and window.open() don't. Add rel=\"noopener noreferrer\" for external links.",
        "examples": {"match": ["<a href=\"https://partner.example\" target=\"_blank\">Partner</a>"], "no_match": ["<a href=\"https://partner.example\" target=\"_blank\" rel=\"noopener noreferrer\">Partner</a>"]},
    },
]

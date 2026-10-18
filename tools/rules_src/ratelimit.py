"""sk-ratelimit rules."""

SKILL = "sk-ratelimit"

MACROS = {
    "AUTH_ROUTE": r"['\"`][^'\"`\s]*/(login|signin|sign-in|signup|sign-up|register|sessions?|authenticate|auth/token|oauth/token|token|forgot\w*|reset\w*|password\w*|otp|mfa|2fa|totp|verify\w*|magic[-_]?link)['\"`]",
    "EXPENSIVE_ROUTE": r"['\"`][^'\"`\s]*/(search|export\w*|report\w*|download\w*|generate\w*|render\w*|convert\w*|import\w*|bulk\w*|batch\w*|chat|complete\w*|ai|llm|summari\w*|analy[sz]\w*|pdf|thumbnail\w*|resize)['\"`]",
    "SEND_CALL": r"(?i:sendMail|send_mail|transporter\.send|\.messages\.create\(|sns\.publish|sendSms|send_sms|sendEmail|send_email|sgMail\.send|mailgun|postmark|resend\.emails\.send|sendPush|webpush\.send|fcm|apns|invite\w*\()",
    "ENUM_ROUTE": r"['\"`][^'\"`\s]*/(check[-_]?(email|username|user|availability)|exists|lookup|validate[-_]?(coupon|code|invite|voucher)|coupons?/[:{]|invites?/[:{]|gift[-_]?cards?/[:{]|redeem\w*|available)['\"`]",
}

RULES = [
    {
        "id": "rl-auth-no-limit", "check_id": "RL-AUTH-001", "type": "absence", "scope": "project",
        "title": "Authentication endpoints with no rate limiting anywhere in the project",
        "files": ["code", "config"], "when": "{{AUTH_ROUTE}}", "missing": "{{RATE_LIMIT}}|(?i:captcha|turnstile|hcaptcha|recaptcha)",
        "confidence": "MEDIUM", "note": "Check gateway/WAF/proxy limits outside the repo before confirming.",
        "examples": {"match": ["app.post('/api/login', login)"], "no_match": ["app.post('/api/login', loginLimiter, login)"]},
    },
    {
        "id": "rl-expensive-no-limit", "check_id": "RL-EXP-001", "type": "absence", "scope": "project",
        "title": "Expensive endpoints with no rate limiting or quota anywhere in the project",
        "files": ["code", "config"], "when": "{{EXPENSIVE_ROUTE}}", "missing": "{{RATE_LIMIT}}|(?i:quota|budget|usage_?limit|credits)",
        "confidence": "MEDIUM",
        "examples": {"match": ["router.get('/export', exportCsv)"], "no_match": ["router.get('/export', exportLimiter, exportCsv)"]},
    },
    {
        "id": "rl-send-no-limit", "check_id": "RL-SEND-001", "type": "absence", "scope": "file",
        "title": "Messages sent from a request handler with no throttling in the file",
        "files": ["code"], "when": "{{SEND_CALL}}", "file_requires": "{{SRC}}",
        "missing": "{{RATE_LIMIT}}|(?i:cooldown|last_?sent|sent_?at|resend_?after|max_?per|attempts|quota)",
        "confidence": "MEDIUM", "note": "Unthrottled SMS endpoints are used for toll fraud (SMS pumping); email endpoints for spam relays.",
        "examples": {"match": ["app.post('/send-code', async (req, res) => { await client.messages.create({ to: req.body.phone, body }); })"],
                     "no_match": ["app.post('/send-code', smsLimiter, async (req, res) => { await client.messages.create({ to: req.body.phone, body }); })"]},
    },
    {
        "id": "rl-enum-no-limit", "check_id": "RL-ENUM-001", "type": "absence", "scope": "project",
        "title": "Existence/lookup endpoints with no rate limiting",
        "files": ["code", "config"], "when": "{{ENUM_ROUTE}}", "missing": "{{RATE_LIMIT}}", "confidence": "LOW",
        "examples": {"match": ["router.get('/check-email', checkEmail)"], "no_match": ["router.get('/check-email', limiter, checkEmail)"]},
    },
    {
        "id": "rl-global-only-key", "check_id": "RL-KEY-001", "title": "Rate limit keyed on a constant (one global bucket)",
        "files": ["code"],
        "pattern": r"(keyGenerator|key_func|key)\s*[:=]\s*(\(\s*\)\s*=>\s*['\"`][^'\"`]*['\"`]|lambda\s*:\s*['\"][^'\"]*['\"]|['\"]global['\"])",
        "near": {"pattern": r"(?i)(limit|throttl)", "lines": 6}, "confidence": "MEDIUM",
        "note": "A single shared bucket lets one client exhaust everyone's quota and does not slow per-account guessing.",
        "examples": {"match": ["rateLimit({ windowMs: 60e3, max: 100, keyGenerator: () => 'global' })"], "no_match": ["rateLimit({ windowMs: 60e3, max: 5, keyGenerator: (req) => req.body.email + req.ip })"]},
    },
    {
        "id": "rl-trust-proxy-true", "check_id": "RL-IP-001", "title": "All proxies trusted for the client IP",
        "files": ["code", "config"],
        "pattern": r"app\.set\(\s*['\"]trust proxy['\"]\s*,\s*(true|['\"]true['\"])\s*\)|trustProxy\s*:\s*true|ForwardedHeadersOptions[\s\S]{0,200}KnownNetworks\.Clear\(\)|server\.forward-headers-strategy\s*=\s*native|USE_X_FORWARDED_HOST\s*=\s*True|proxy_set_header\s+X-Forwarded-For\s+\$http_x_forwarded_for",
        "confidence": "HIGH", "note": "With `true`, the left-most X-Forwarded-For value (client-supplied) becomes req.ip; set the exact number of proxy hops or their addresses.",
        "examples": {"match": ["app.set('trust proxy', true);"], "no_match": ["app.set('trust proxy', 1);"]},
    },
    {
        "id": "rl-xff-first-entry", "check_id": "RL-IP-001", "title": "Client IP taken from the first X-Forwarded-For entry",
        "files": ["code"],
        "pattern": r"(?i)(x-forwarded-for|HTTP_X_FORWARDED_FOR|X-Real-IP|cf-connecting-ip|true-client-ip)['\"]?\]?\)?[^\n]{0,40}(\.split\(\s*['\"],\s*['\"]\s*\)\s*\[\s*0\s*\]|\.split\(\s*['\"],['\"]\s*\)\s*\[\s*0\s*\]|\.split\(\s*','\s*\)\[0\]|\[0\]|\.First|\.split\(\s*\",\"\s*\)\[0\])|(x-forwarded-for|X-Real-IP)['\"]?\]?\)?\s*(\|\||\?\?|or)\s*(req\.|request\.|r\.)",
        "confidence": "HIGH", "note": "Clients can set these headers; only the entries added by your own proxies are trustworthy.",
        "examples": {"match": ["const ip = req.headers['x-forwarded-for'].split(',')[0];", "ip = request.headers.get('X-Forwarded-For') or request.remote_addr"], "no_match": ["const ip = req.ip;"]},
    },
    {
        "id": "rl-memory-store", "check_id": "RL-STORE-001", "title": "Rate limiter uses per-process memory",
        "files": ["code", "config"],
        "pattern": r"(?i)MemoryStore\(|storage_uri\s*=\s*['\"]memory://|RATELIMIT_STORAGE_URI\s*=\s*['\"]memory://|new\s+RateLimiterMemory\(|InMemoryRateLimiter|cache\s*:\s*new\s+Map\(\)",
        "confidence": "LOW", "note": "Each instance counts separately; N instances allow N times the limit.",
        "examples": {"match": ["limiter = Limiter(app, storage_uri='memory://')"], "no_match": ["limiter = Limiter(app, storage_uri='redis://redis:6379')"]},
    },
    {
        "id": "rl-express-default-store", "check_id": "RL-STORE-001", "title": "express-rate-limit without a shared store",
        "files": ["js"], "pattern": r"\brateLimit\(\s*\{", "not_near": {"pattern": r"\bstore\s*:", "lines": 8},
        "confidence": "LOW",
        "examples": {"match": ["const limiter = rateLimit({ windowMs: 60e3, max: 10 });"], "no_match": ["const limiter = rateLimit({ windowMs: 60e3, max: 10, store: new RedisStore({ client }) });"]},
    },
    {
        "id": "rl-skip-condition", "check_id": "RL-BYPASS-001", "title": "Rate limiter skip condition based on request data",
        "files": ["code"],
        "pattern": r"(?i)\b(skip|exempt|whitelist|allowlist|bypass)\w*\s*[:=]\s*(\(?\s*req\b[^\n]*(headers|query|body|get\(|ip\b|user-agent)|lambda\s*:?\s*request\.(headers|args)|['\"]X-[\w-]+['\"])",
        "near": {"pattern": r"(?i)(limit|throttl)", "lines": 8}, "confidence": "MEDIUM",
        "examples": {"match": ["rateLimit({ max: 5, skip: (req) => req.headers['x-internal'] === '1' })"], "no_match": ["rateLimit({ max: 5, skipSuccessfulRequests: true })"]},
    },
    {
        "id": "rl-limiter-on-exact-path", "check_id": "RL-BYPASS-001", "title": "Limiter mounted on an exact path string (variants may bypass it)",
        "files": ["js"], "pattern": r"app\.use\(\s*['\"]/[^'\"]*(login|signin|auth|reset|otp)[^'\"]*['\"]\s*,\s*\w*([lL]imit|[tT]hrottl)",
        "confidence": "LOW", "note": "Check case-insensitive routing, trailing slashes and versioned/alias routes reach the same limiter.",
        "examples": {"match": ["app.use('/api/login', loginLimiter)"], "no_match": ["router.post('/login', loginLimiter, login)"]},
    },
    {
        "id": "rl-unbounded-page-size", "check_id": "RL-QUOTA-001", "title": "Page size taken from the request without a maximum",
        "files": ["code"],
        "pattern": r"(?i)\b(limit|take|page_?size|per_?page|size|first|count|top)\s*[:=]\s*(parseInt|Number|int|toInt|Integer\.parseInt)?\(?\s*({{SRC}})[\w.\[\]'\"]*\)?\s*(\|\||\?\?|or)?",
        "not_near": {"pattern": r"(?i)(Math\.min|min\(|clamp|max_?(limit|page)|MAX_|\.max\(|le\s*=|Field\([^)]*le=|<=\s*\d)", "lines": 2},
        "confidence": "MEDIUM",
        "examples": {"match": ["const limit = parseInt(req.query.limit) || 20;"], "no_match": ["const limit = Math.min(parseInt(req.query.limit) || 20, 100);"]},
    },
    {
        "id": "rl-no-429-handler", "check_id": "RL-RESP-001", "title": "Rate-limit rejection does not return 429",
        "files": ["code"],
        "pattern": r"(?i)(statusCode|status_code|status)\s*[:=]\s*(4(0[0-3]|04)|5\d\d)\b", "near": {"pattern": r"(?i)(too many|rate.?limit|throttl)", "lines": 3},
        "confidence": "LOW",
        "examples": {"match": ["rateLimit({ max: 5, statusCode: 403, message: 'Too many requests' })"], "no_match": ["rateLimit({ max: 5, statusCode: 429 })"]},
    },
]

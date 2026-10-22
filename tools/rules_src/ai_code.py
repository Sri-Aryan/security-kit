"""sk-ai-code rules: patterns typical of AI-written ("vibe-coded") code that ships insecure.

Placeholder auth, security TODOs, checks switched off to make an error go away, mass assignment, secret fallbacks,
missing ownership checks, debug routes and provider keys in the browser. Hallucinated packages are checked by
scripts/phantom_deps.py, not by these rules.
"""

SKILL = "sk-ai-code"

MACROS = {
    "OWNER_CHECK": r"(?i:userId|user_id|ownerId|owner_id|authorId|author_id|createdBy|created_by|tenantId|tenant_id|orgId|org_id|accountId|account_id|session\.user|currentUser|current_user|request\.user|req\.user|ctx\.user|auth\.uid|getUser|auth\(\)|can\(|authorize|policy|ability|forbidden|403)",
    "BODY": r"req\.body|request\.body|await\s+req\.json\(\)|await\s+request\.json\(\)|await\s+c\.req\.json\(\)|ctx\.request\.body|request\.(json|data|POST|form)\b|request\.get_json\(\)",
}

RULES = [
    # ------------------------------------------------------------------ PLACEHOLDER AUTH
    {
        "id": "aicode-auth-bypass-flag", "check_id": "AICODE-STUB-001", "title": "Auth bypass switch in code", "files": ["code", "env", "config"],
        "pattern": r"\b(SKIP_AUTH|BYPASS_AUTH|DISABLE_AUTH|AUTH_DISABLED|NO_AUTH|DEV_BYPASS|AUTH_BYPASS|MOCK_AUTH|FAKE_AUTH|DISABLE_RLS)\b",
        "confidence": "MEDIUM", "note": "Confirm the switch cannot be on in production (unset env must mean auth ON).",
        "examples": {"match": ["if (process.env.SKIP_AUTH) return next();"], "no_match": ["if (!session) return unauthorized();"]},
    },
    {
        "id": "aicode-hardcoded-authorized", "check_id": "AICODE-STUB-001", "title": "Authorization hard-coded to true", "files": ["code"],
        "pattern": r"(?i)\b(const|let|var|)\s*(is_?admin|is_?authenticated|is_?authorized|is_?logged_?in|has_?access|can_?access|authorized|allowed)\s*(:\s*\w+\s*)?=\s*(true|True)\s*;?\s*($|//|#)",
        "path_excludes": r"(?i)(seed|fixture|mock|stories|\.test\.|\.spec\.|/tests?/)", "confidence": "MEDIUM",
        "examples": {"match": ["const isAdmin = true; // TODO real check", "is_authenticated = True"], "no_match": ["const isAdmin = user.role === 'admin';"]},
    },
    {
        "id": "aicode-mock-user", "check_id": "AICODE-STUB-001", "title": "Hard-coded mock user in request handling", "files": ["code"],
        "pattern": r"(?i)\b(const|let|var)\s+(current_?user|user|session)\s*=\s*\{\s*(id|user_?id|userId)\s*:\s*['\"]?\w{1,12}['\"]?\s*,|(current_?user|user_id|userId)\s*=\s*['\"]?(1|123|test|demo|admin)['\"]?\s*(;|$|//|#)",
        "path_excludes": r"(?i)(seed|fixture|mock|stories|\.test\.|\.spec\.|/tests?/)", "confidence": "MEDIUM",
        "examples": {"match": ["const user = { id: 1, role: 'admin' }; // mock until auth is ready", "const userId = 'demo';"],
                     "no_match": ["const user = await getCurrentUser(req);"]},
    },
    {
        "id": "aicode-return-true-auth", "check_id": "AICODE-STUB-001", "title": "Auth/permission function that always returns true", "files": ["code"],
        "multiline": True,
        "pattern": r"(?i)(function|def|const)\s+\w*(auth|permission|authorize|can_?access|is_?allowed|check_?access|verify)\w*[^{:\n]*[{:]\s*(?:(?://|#)[^\n]*\n\s*)*return\s+(true|True)\b",
        "confidence": "HIGH",
        "examples": {"match": ["function checkPermission(user, resource) {\n  // TODO: implement\n  return true;\n}", "def is_allowed(user, obj):\n    return True"],
                     "no_match": ["function checkPermission(user, resource) {\n  return resource.ownerId === user.id;\n}"]},
    },
    # ------------------------------------------------------------------ TODOs
    {
        "id": "aicode-security-todo", "check_id": "AICODE-TODO-001", "title": "Unresolved security TODO", "files": ["code", "web"],
        "pattern": r"(?i)(//|#|/\*|<!--|--|\*)\s*(TODO|FIXME|XXX|HACK)\b[^\n]*\b(auth|permission|security|secure|validat|sanitiz|escape|csrf|rate.?limit|encrypt|hash|password|token|owner|access control|admin|production|prod)\w*",
        "confidence": "MEDIUM",
        "examples": {"match": ["// TODO: add auth check before deleting", "# FIXME: validate input"], "no_match": ["// TODO: tidy up the CSS"]},
    },
    {
        "id": "aicode-tutorial-caveat", "check_id": "AICODE-TODO-001", "title": "Tutorial caveat left in code (\"in production you should...\")", "files": ["code", "web"],
        "pattern": r"(?i)(//|#|/\*|\*)\s*[^\n]*(in (a )?(real|production) (app|application|environment|system)|for (demo|simplicity|now|this example|testing purposes)|not (secure|safe) for production|should (be|use|add) (proper|real|a real)\s+\w+|replace (this|with) (a )?(real|proper)|this is (insecure|not secure))",
        "confidence": "MEDIUM",
        "examples": {"match": ["// In a real app you should hash this password", "# For simplicity we skip signature verification"], "no_match": ["// Hash the password with argon2id"]},
    },
    # ------------------------------------------------------------------ CHECKS DISABLED
    {
        "id": "aicode-tls-verify-off", "check_id": "AICODE-DISABLED-001", "title": "TLS certificate verification disabled", "files": ["code", "env", "config", "shell", "docker"],
        "pattern": r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=?\s*['\"]?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0)|ServerCertificateValidationCallback\s*=[^;]*=>\s*true|sslmode=disable",
        "confidence": "HIGH", "note": "A classic fix for 'self-signed certificate' errors that also disables protection against interception.",
        "examples": {"match": ["const pool = new Pool({ ssl: { rejectUnauthorized: false } });", "requests.get(url, verify=False)"], "no_match": ["const pool = new Pool({ ssl: { ca: fs.readFileSync('ca.pem') } });"]},
    },
    {
        "id": "aicode-csrf-off", "check_id": "AICODE-DISABLED-001", "title": "CSRF protection switched off", "files": ["code", "config"],
        "pattern": r"(?i)\.csrf\(\s*\w*\s*->\s*\w*\.disable\(\)\s*\)|csrf\(\)\.disable\(\)|@csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False|skip_forgery_protection|protect_from_forgery\s+with:\s*:null_session|csrf\s*:\s*false|VerifyCsrfToken[^\n]*except",
        "confidence": "MEDIUM", "note": "Fine for token-authenticated APIs without cookies; a finding for cookie sessions.",
        "examples": {"match": ["http.csrf(csrf -> csrf.disable());", "@csrf_exempt\ndef update(request):"], "no_match": ["http.csrf(Customizer.withDefaults());"]},
    },
    {
        "id": "aicode-cors-reflect-credentials", "check_id": "AICODE-DISABLED-001", "title": "CORS reflects any origin with credentials", "files": ["code", "config"],
        "pattern": r"(?i)origin\s*:\s*(true|['\"]\*['\"]|\(\s*\w*\s*,\s*\w+\s*\)\s*=>\s*\w+\(\s*null\s*,\s*true\s*\))[^\n]*credentials\s*:\s*true|credentials\s*:\s*true[^\n]*origin\s*:\s*(true|['\"]\*['\"])|allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\][^\n]*allow_credentials\s*=\s*True|AllowAnyOrigin\(\)[^\n]*AllowCredentials\(\)",
        "confidence": "HIGH",
        "examples": {"match": ["app.use(cors({ origin: true, credentials: true }));", "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)"],
                     "no_match": ["app.use(cors({ origin: ['https://app.acme.com'], credentials: true }));"]},
    },
    {
        "id": "aicode-security-lint-suppressed", "check_id": "AICODE-DISABLED-001", "title": "Security linter warning suppressed", "files": ["code"],
        "pattern": r"(?i)eslint-disable[^\n]*(security|no-eval|no-implied-eval|react/no-danger)|#\s*nosec\b|#\s*noqa:\s*S\d+|@SuppressWarnings\(\s*\"(java:S|squid:S)\d+|//\s*NOSONAR|#\s*nosemgrep|//\s*nosemgrep",
        "confidence": "LOW",
        "examples": {"match": ["// eslint-disable-next-line security/detect-object-injection", "subprocess.call(cmd, shell=True)  # nosec"], "no_match": ["// eslint-disable-next-line no-console"]},
    },
    # ------------------------------------------------------------------ MASS ASSIGNMENT
    {
        "id": "aicode-mass-assign-body", "check_id": "AICODE-MASS-001", "title": "Request body written straight to the database", "files": ["code"],
        "pattern": r"\.(create|insert|insertOne|insertMany|update|updateOne|updateMany|upsert|findOneAndUpdate|findByIdAndUpdate|save|values|set)\(\s*([^()\n]*?(\bdata\s*:|,))?\s*(\.\.\.)?({{BODY}})\s*[,)}]|\.(create|update|upsert)\(\s*\{\s*data\s*:\s*\{\s*\.\.\.({{BODY}}|body|input|data)\s*[,}]",
        "confidence": "HIGH", "note": "A client can add role, isAdmin, credits, ownerId or price to the body. Pick allowed fields explicitly (schema with strict/unknown-keys stripping).",
        "examples": {"match": ["await prisma.user.update({ where: { id }, data: req.body });", "await User.findByIdAndUpdate(id, req.body);", "await prisma.post.create({ data: { ...body, authorId } })"],
                     "no_match": ["await prisma.user.update({ where: { id }, data: { name: parsed.name } });"]},
    },
    {
        "id": "aicode-mass-assign-spread", "check_id": "AICODE-MASS-001", "title": "Object built by spreading the request body or assigning it wholesale", "files": ["code"],
        "pattern": r"Object\.assign\(\s*\w+\s*,\s*({{BODY}})\s*\)|\b\w+\(\s*\*\*\s*({{BODY}})\s*\)|\.update\(\s*\*\*\s*({{BODY}})|\bnew\s+[A-Z]\w*\(\s*({{BODY}})\s*\)|->(fill|update|create)\(\s*\$request->all\(\)\s*\)|\.(update|create)\(\s*params\.permit!\s*\)",
        "confidence": "HIGH",
        "examples": {"match": ["Object.assign(user, req.body);", "user = User(**request.json)", "$user->update($request->all());"],
                     "no_match": ["user = User(name=data['name'])"]},
    },
    # ------------------------------------------------------------------ SECRETS
    {
        "id": "aicode-secret-env-fallback", "check_id": "AICODE-SECRET-001", "title": "Secret falls back to a hard-coded value", "files": ["code"],
        "pattern": r"process\.env\.{{SECRET_NAME}}\s*(\|\||\?\?)\s*['\"`][^'\"`\s]{2,}['\"`]|os\.(environ\.get|getenv)\(\s*['\"]{{SECRET_NAME}}['\"]\s*,\s*['\"][^'\"]{2,}['\"]\s*\)|os\.environ\.get\(\s*['\"]{{SECRET_NAME}}['\"]\s*\)\s*or\s*['\"][^'\"]{2,}['\"]|ENV\.fetch\(\s*['\"]{{SECRET_NAME}}['\"]\s*,\s*['\"][^'\"]{2,}['\"]",
        "confidence": "HIGH", "note": "If the variable is missing in production the app silently signs tokens with a value that is in your repository. Fail at start-up instead.",
        "examples": {"match": ["const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';", "SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret')"],
                     "no_match": ["const JWT_SECRET = process.env.JWT_SECRET!;", "PORT = os.environ.get('PORT', '8000')"]},
    },
    {
        "id": "aicode-tutorial-secret", "check_id": "AICODE-SECRET-001", "title": "Tutorial placeholder used as a real secret", "files": ["code", "config", "env"],
        "pattern": r"(?i)[:=]\s*['\"]?(your[-_ ]?(super[-_ ]?)?(secret|jwt|api|session)[-_ ]?(key|secret)?[\w-]*|super[-_]?secret[\w-]*|secret123|my[-_]?secret[-_]?key|keyboard cat|shhhh+|changeme|change[-_]me)['\"]?\s*(,|;|$|\)|\})",
        "near": {"pattern": r"(?i)secret|jwt|session|sign|key", "lines": 0}, "confidence": "HIGH",
        "examples": {"match": ["app.use(session({ secret: 'keyboard cat' }));", "JWT_SECRET=your-secret-key"], "no_match": ["app.use(session({ secret: process.env.SESSION_SECRET }));"]},
    },
    # ------------------------------------------------------------------ OWNERSHIP
    {
        "id": "aicode-fetch-by-id-no-owner", "check_id": "AICODE-AUTHZ-001", "title": "Record loaded/changed by an ID from the request with no owner check", "files": ["code"],
        "pattern": r"\.(findUnique|findFirst|findById|findByPk|findOne|findOneAndUpdate|findOneAndDelete|findByIdAndUpdate|findByIdAndDelete|delete|update|destroy|get_object_or_404|get)\(\s*[^\n]{0,40}?(req\.params\.\w+|params\.\w*[iI]d\b|ctx\.params\.\w+|req\.query\.\w*[iI]d\b|request\.args\.get\(\s*['\"]\w*id['\"]|\bid\s*=\s*\w*id\b|pk\s*=\s*\w*pk\b)",
        "not_near": {"pattern": "{{OWNER_CHECK}}", "lines": 6}, "confidence": "MEDIUM",
        "note": "Insecure direct object reference: any signed-in user can read or change anyone's record by changing the ID. Filter by owner/tenant in the same query.",
        "examples": {"match": ["const order = await prisma.order.findUnique({ where: { id: params.id } });", "post = Post.objects.get(id=post_id)"],
                     "no_match": ["const order = await prisma.order.findFirst({ where: { id: params.id, userId: session.user.id } });"]},
    },
    # ------------------------------------------------------------------ DEBUG / ERRORS / CLIENT
    {
        "id": "aicode-debug-route", "check_id": "AICODE-DEBUG-001", "title": "Debug, seed or reset route", "files": ["code"],
        "pattern": r"(?i)['\"`]/(api/)?(seed|debug|reset[-_]?(db|database)|dev[-_]?login|backdoor|make[-_]?admin|promote|run[-_]?sql|sql|exec|eval|phpinfo|test[-_]?(login|email|user))(/[^'\"`]*)?['\"`]",
        "confidence": "MEDIUM", "note": "Delete it, or gate it on an admin check AND a non-production environment.",
        "examples": {"match": ["app.post('/api/seed', seedDatabase);", "router.get('/debug', (req, res) => res.json(process.env));"], "no_match": ["app.post('/api/orders', createOrder);"]},
    },
    {
        "id": "aicode-debug-route-file", "check_id": "AICODE-DEBUG-001", "title": "Debug, seed or reset route file", "files": ["js", "py"],
        "path_includes": r"(?i)(^|/)(pages|app|routes|api)/(api/)?(seed|debug|reset-?db|dev-?login|make-?admin|test-?(login|email))(/|\.|$)",
        "pattern": r"export\s+(default|async|const|function)|^def\s|@\w+\.(get|post|route)", "confidence": "HIGH",
        "examples": {"match": ["export async function POST() { await seed(); }"], "no_match": ["const x = 1;"]},
    },
    {
        "id": "aicode-env-dump", "check_id": "AICODE-DEBUG-001", "title": "Whole environment returned or logged", "files": ["code"],
        "pattern": r"(res\.(json|send)|Response\.json|NextResponse\.json|jsonify|return)\(?\s*(process\.env|os\.environ|dict\(os\.environ\))\s*\)?|console\.log\(\s*process\.env\s*\)|print\(\s*os\.environ\s*\)",
        "confidence": "HIGH",
        "examples": {"match": ["res.json(process.env);", "console.log(process.env);"], "no_match": ["res.json({ ok: true });"]},
    },
    {
        "id": "aicode-raw-error-to-client", "check_id": "AICODE-ERR-001", "title": "Raw error message or stack sent to the client", "files": ["code"],
        "pattern": r"(\.json|\.send|jsonify|Response\.json|NextResponse\.json|HttpResponse)\(\s*(\{\s*\w+\s*:\s*)?(err|error|e|ex|exc)\.(message|stack|toString\(\))|(\.json|\.send)\(\s*(err|error|e)\s*\)|['\"](error|detail|message)['\"]\s*:\s*str\(\s*(e|ex|exc|err|error)\s*\)",
        "confidence": "MEDIUM", "note": "Database and library errors reveal table names, queries, file paths and sometimes data. Log the detail, return a generic message.",
        "examples": {"match": ["} catch (err) { res.status(500).json({ error: err.message }); }", "return jsonify({'error': str(e)}), 500"],
                     "no_match": ["} catch (err) { logger.error(err); res.status(500).json({ error: 'Internal error' }); }"]},
    },
    {
        "id": "aicode-llm-key-in-browser", "check_id": "AICODE-CLIENT-001", "title": "AI provider SDK allowed to run in the browser", "files": ["js", "web"],
        "pattern": r"dangerouslyAllowBrowser\s*:\s*true", "confidence": "HIGH",
        "note": "The API key ships to every visitor; anyone can spend your quota. Call the provider from a server route with per-user limits.",
        "examples": {"match": ["const openai = new OpenAI({ apiKey, dangerouslyAllowBrowser: true });"], "no_match": ["const openai = new OpenAI();"]},
    },
    {
        "id": "aicode-provider-call-from-frontend", "check_id": "AICODE-CLIENT-001", "title": "Paid API called directly from frontend code", "files": ["js", "web"],
        "pattern": r"https://(api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.groq\.com|api\.mistral\.ai|api\.stripe\.com|api\.resend\.com|api\.sendgrid\.com)",
        "path_excludes": r"(?i)(/api/|/server/|\.server\.|/functions/|/actions?/|route\.[jt]s$|/lib/server/|/backend/)",
        "file_requires": r"(?:^|\n)[ \t]*['\"]use client['\"]|\buseState\b|\bonClick\b|document\.|window\.",
        "confidence": "MEDIUM",
        "examples": {"match": ["'use client';\nconst r = await fetch('https://api.openai.com/v1/chat/completions', { headers: { Authorization: `Bearer ${key}` } });"],
                     "no_match": ["const r = await fetch('/api/chat', { method: 'POST' });"]},
    },
]

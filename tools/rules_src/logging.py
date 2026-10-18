"""sk-logging rules: sensitive data in logs, swallowed errors, missing security events, error-tracker privacy."""

SKILL = "sk-logging"

MACROS = {
    "SENSITIVE_WORD": r"(?:password|passwd|pwd|secret|token|access_?token|accessToken|refresh_?token|refreshToken|api_?key|apiKey|authorization|cookie|session_?id|sessionId|ssn|card_?number|cardNumber|cvv|cvc|pin)",
    "LOG_LIB": r"(?i:winston|pino|bunyan|log4js|loglevel|signale|consola|structlog|logging\.getLogger|loguru|slf4j|logback|log4j|java\.util\.logging|zap\.|zerolog|logrus|log/slog|\bslog\.|Serilog|NLog|ILogger|Monolog|Rails\.logger|Logger\.new|tracing::|env_logger)",
}

RULES = [
    # ------------------------------------------------------------------ SENSITIVE
    {
        "id": "log-sensitive-variable", "check_id": "LOG-SENSITIVE-001", "title": "Secret or credential value written to a log", "files": ["code"],
        "pattern": r"(?i){{LOG_CALL}}[^\n]*(\$\{|\{|,|\+|%\s*|=|\()\s*[\w.\[\]'\"]*?{{SENSITIVE_WORD}}\w*['\"]?\s*[}),+\]]",
        "not_near": {"pattern": r"(?i)(redact|mask|\*\*\*|scrub|sanitize|omit|censor)", "lines": 1},
        "confidence": "MEDIUM",
        "examples": {"match": ["logger.info('login attempt', { email, password });", "console.log(`token=${user.accessToken}`);", "log.Printf(\"auth header %s\", r.Header.Get(\"Authorization\"))"],
                     "no_match": ["logger.warn('Invalid password for user', { userId });", "logger.info('login', redact({ email, password }));"]},
    },
    {
        "id": "log-request-dump", "check_id": "LOG-SENSITIVE-001", "title": "Whole request body/headers written to a log", "files": ["code"],
        "pattern": r"{{LOG_CALL}}[^\n]*\b(req\.(body|headers|cookies)\b|request\.(json|data|body|headers|form|POST|cookies|get_json\(\))|JSON\.stringify\(\s*req\s*\)|request\.META\b|HttpServletRequest|ctx\.request\.(body|headers))",
        "confidence": "MEDIUM", "note": "Bodies carry passwords and personal data; headers carry Authorization and cookies. Log selected fields.",
        "examples": {"match": ["console.log('incoming', req.body);", "logger.debug(f'payload {request.json}')"],
                     "no_match": ["logger.info('order created', { orderId: order.id, userId: req.user.id });"]},
    },
    {
        "id": "log-whole-user-object", "check_id": "LOG-SENSITIVE-001", "title": "Whole user/customer record written to a log", "files": ["code"],
        "pattern": r"{{LOG_CALL}}[^\n]*[,(]\s*(JSON\.stringify\(\s*)?(user|account|customer|patient|member|profile)\s*\)?\s*[,)]",
        "confidence": "LOW",
        "examples": {"match": ["console.log('signed up', user);"], "no_match": ["console.log('signed up', user.id);"]},
    },
    {
        "id": "log-tracker-pii-on", "check_id": "LOG-CLIENT-001", "title": "Error tracker / session replay configured to collect PII or unmasked input", "files": ["code", "config"],
        "pattern": r"send_default_pii\s*=\s*True|sendDefaultPii\s*:\s*true|mask(AllText|AllInputs)\s*:\s*false|maskAllInputs\s*:\s*false|inputSanitizer\s*:\s*false|recordHeadersAndBody\s*:\s*true|dom\.isEnabled\s*:\s*true",
        "confidence": "HIGH",
        "examples": {"match": ["sentry_sdk.init(dsn=DSN, send_default_pii=True)", "Sentry.replayIntegration({ maskAllText: false })"],
                     "no_match": ["sentry_sdk.init(dsn=DSN, send_default_pii=False)"]},
    },
    # ------------------------------------------------------------------ INJECT
    {
        "id": "log-user-input-concat", "check_id": "LOG-INJECT-001", "title": "Raw request input concatenated into a log line", "files": ["code"],
        "pattern": r"{{LOG_CALL}}[^\n]*(\+\s*|\$\{\s*|%\s*\(?|f['\"][^'\"\n]*\{[^}]*?)({{SRC}})",
        "confidence": "LOW", "note": "Newlines in the value can forge entries. Use structured fields or encode CR/LF.",
        "examples": {"match": ["console.log('search: ' + req.query.q);", "logger.info(f\"user {request.args.get('u')} logged in\")"],
                     "no_match": ["logger.info('search', { q: req.query.q });"]},
    },
    # ------------------------------------------------------------------ ERROR
    {
        "id": "log-empty-catch", "check_id": "LOG-ERROR-001", "title": "Error silently swallowed", "files": ["code"], "multiline": True,
        "pattern": r"catch\s*(\([^)]*\))?\s*\{\s*\}|except(\s+[\w.(), ]+)?(\s+as\s+\w+)?\s*:\s*\n\s*pass\b|rescue(\s+[\w:]+)?(\s*=>\s*\w+)?\s*\n\s*(nil\s*\n\s*)?end\b|\.catch\(\s*\(\s*\w*\s*\)\s*=>\s*\{\s*\}\s*\)|\.catch\(\s*\(\)\s*=>\s*(null|undefined|\{\s*\})\s*\)",
        "confidence": "MEDIUM", "note": "Silent failures hide attacks and broken security controls (e.g. a signature check that throws).",
        "examples": {"match": ["try { verify(sig) } catch (e) {}", "try:\n    verify(sig)\nexcept Exception:\n    pass", "await audit(e).catch(() => {});"],
                     "no_match": ["try { verify(sig) } catch (e) { logger.warn('bad signature', { err: e.message }); throw e; }"]},
    },
    # ------------------------------------------------------------------ LEVEL
    {
        "id": "log-debug-level-config", "check_id": "LOG-LEVEL-001", "title": "Debug/trace log level configured", "files": ["code", "config", "env"],
        "pattern": r"(?i)(\blevel|LOG_LEVEL|LOGLEVEL|logging\.level\.\w+(\.\w+)*|RUST_LOG|log_level)\s*[:=]\s*['\"]?(debug|trace|silly|verbose|all)\b|logging\.basicConfig\([^)]*level\s*=\s*logging\.DEBUG",
        "path_excludes": r"(?i)(dev|local|test|spec|example|sample|\.development)", "confidence": "LOW",
        "examples": {"match": ["LOG_LEVEL=debug", "logging.basicConfig(level=logging.DEBUG)"], "no_match": ["LOG_LEVEL=info"]},
    },
    # ------------------------------------------------------------------ EVENTS
    {
        "id": "log-login-not-logged", "check_id": "LOG-EVENTS-001", "type": "absence", "scope": "file",
        "title": "Login/authentication handler that logs nothing", "files": ["code"],
        "when": r"(?i)(def|function|func|fun|async\s+function|const|let|public|private)\s+\w*(login|signin|sign_in|authenticate|verify_?otp|verifyMfa)\w*\s*(=|\()",
        "missing": "{{LOG_CALL}}|(?i:audit|emit\\(\\s*['\"](login|auth))",
        "confidence": "LOW",
        "examples": {"match": ["async function login(req, res) {\n  const ok = await check(req.body.email, req.body.password);\n  if (!ok) return res.status(401).end();\n}"],
                     "no_match": ["async function login(req, res) {\n  const ok = await check(req.body.email, req.body.password);\n  if (!ok) { logger.warn('login_failed', { email: req.body.email }); return res.status(401).end(); }\n}"]},
    },
    {
        "id": "log-denied-not-logged", "check_id": "LOG-EVENTS-001", "type": "absence", "scope": "project",
        "title": "Access-denied responses are never logged", "files": ["code"],
        "when": r"\.status\(\s*403\s*\)|HTTP_403|status_code\s*=\s*403|Forbidden\(\)|HttpStatus\.FORBIDDEN|http\.StatusForbidden|abort\(\s*403",
        "missing": r"(?i)(access_?denied|forbidden|authz_?fail|permission_?denied|unauthori[sz]ed)['\"]?\s*[,)]|audit",
        "confidence": "LOW",
        "examples": {"match": ["if (!can(user, 'read', doc)) return res.status(403).end();"],
                     "no_match": ["if (!can(user, 'read', doc)) { logger.warn('access_denied', { userId, docId }); return res.status(403).end(); }"]},
    },
    # ------------------------------------------------------------------ FORMAT
    {
        "id": "log-no-logging-library", "check_id": "LOG-FORMAT-001", "type": "absence", "scope": "project",
        "title": "Server code logs only with print/console (no logging library)", "files": ["code"],
        "when": r"\bconsole\.(log|error|warn)\(|\bprint\(|System\.out\.println|\bfmt\.Println|\bputs\b",
        "file_requires": "{{SRC}}", "missing": "{{LOG_LIB}}", "confidence": "LOW",
        "examples": {"match": ["app.post('/login', (req, res) => { console.log('login', req.body.email); });"],
                     "no_match": ["const logger = require('pino')();\napp.post('/login', (req, res) => { console.log('login', req.body.email); });"]},
    },
    {
        "id": "log-no-correlation-id", "check_id": "LOG-FORMAT-001", "type": "absence", "scope": "project",
        "title": "No request/correlation ID in logs", "files": ["code"],
        "when": "{{LOG_LIB}}", "file_requires": "{{SRC}}",
        "missing": r"(?i)(request_?id|requestId|correlation_?id|correlationId|trace_?id|traceId|x-request-id|pino-http|morgan|express-winston|asgi-correlation-id|django-guid|opentelemetry|@opentelemetry|otel|MDC\.put|LogContext\.PushProperty)",
        "confidence": "LOW",
        "examples": {"match": ["const logger = require('pino')();\napp.get('/x', (req, res) => logger.info('x', { q: req.query.q }));"],
                     "no_match": ["const pinoHttp = require('pino-http');\nconst logger = require('pino')();\napp.get('/x', (req, res) => logger.info('x', { q: req.query.q }));"]},
    },
]

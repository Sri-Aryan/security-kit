"""sk-rest rules (OWASP REST Security Cheat Sheet)."""

SKILL = "sk-rest"

MACROS = {
    "WEB_APP": r"express\(\)|fastify\(|new\s+Koa\(|new\s+Hono\(|Flask\(__name__|FastAPI\(|django|@RestController|@SpringBootApplication|gin\.(Default|New)\(|echo\.New\(|chi\.NewRouter\(|http\.NewServeMux\(|WebApplication\.CreateBuilder|Rails\.application|Sinatra|Laravel|NestFactory",
    "ROUTE_FILE": r"(?i)(route|controller|handler|view|api|endpoint|resource|server|app)\w*\.",
}

RULES = [
    # ------------------------------------------------------------------ TLS
    {
        "id": "rest-http-base-url", "check_id": "REST-TLS-001", "title": "API base URL over plain HTTP",
        "files": ["code", "config", "env"],
        "pattern": r"(?i)\b(base_?url|api_?url|api_?base|endpoint|server_?url|backend_?url|service_?url)\w*['\"]?\s*[:=]\s*['\"]?http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal|[\w-]+:\d+/?['\"]?$)",
        "confidence": "MEDIUM",
        "examples": {"match": ["API_BASE_URL=http://api.example.com/v1"], "no_match": ["API_BASE_URL=https://api.example.com/v1", "API_URL=http://localhost:8080"]},
    },
    # ------------------------------------------------------------------ ACCESS
    {
        "id": "rest-handler-without-middleware", "check_id": "REST-ACCESS-001", "title": "State-changing route registered with no middleware",
        "files": ["js"],
        "pattern": r"\b(app|router|api|routes)\.(post|put|patch|delete)\(\s*['\"`][^'\"`]+['\"`]\s*,\s*(async\s+)?(\([^)]*\)\s*=>|function\b|\w+Controller\.\w+\s*\))",
        "not_near": {"pattern": r"(?i)['\"`][^'\"`]*/(login|logout|signin|signup|register|auth|token|webhook|health|status|public)", "lines": 0},
        "confidence": "LOW", "note": "Fine if auth is applied at the router or mount; confirm.",
        "examples": {"match": ["router.delete('/items/:id', async (req, res) => {"], "no_match": ["router.delete('/items/:id', requireAuth, async (req, res) => {"]},
    },
    {
        "id": "rest-record-by-id-unscoped", "check_id": "REST-ACCESS-002", "title": "Record loaded by a URL ID without an owner/tenant condition",
        "files": ["code"],
        "pattern": r"(findById|findByPk|findUnique|get_object_or_404|objects\.get|findOne|find_by|\.First\(|\.Find\()\s*\(?[^)\n]*\b(req\.params|params\[|request\.(view_args|match_info)|kwargs\[|path_params|@PathVariable|c\.Param\(|mux\.Vars)",
        "not_near": {"pattern": r"(?i)(user_?id|owner|tenant|account_?id|org_?id|req\.user|request\.user|current_?user|claims|principal)", "lines": 2},
        "confidence": "LOW",
        "examples": {"match": ["const order = await Order.findByPk(req.params.id);"], "no_match": ["const order = await Order.findOne({ where: { id: req.params.id, userId: req.user.id } });"]},
    },
    # ------------------------------------------------------------------ JWT / KEY
    {
        "id": "rest-jwt-decode-only", "check_id": "REST-JWT-001", "title": "JWT decoded without verification",
        "files": ["code"],
        "pattern": r"\bjwt\.decode\(\s*[^,()]+\)|\bjwtDecode\(|jose\.decodeJwt\(|get_unverified_claims\(|['\"]verify_signature['\"]\s*:\s*False|ParseUnverified\(|parseClaimsJwt\(",
        "near": {"pattern": r"(?i)(jwt|token|bearer|claims)", "lines": 3}, "confidence": "HIGH",
        "examples": {"match": ["const claims = jwt.decode(token);"], "no_match": ["const claims = jwt.verify(token, key, { algorithms: ['RS256'], audience: 'api', issuer: ISS });"]},
    },
    {
        "id": "rest-jwt-alg-none-or-exp-off", "check_id": "REST-JWT-001", "title": "JWT 'none' algorithm or expiry/audience validation disabled",
        "files": ["code", "config"],
        "pattern": r"(?i)algorithms?['\"]?\s*[:=]\s*\[?[^\]\n]*['\"]none['\"]|ignoreExpiration\s*:\s*true|['\"]verify_(exp|aud|iss)['\"]\s*:\s*False|Validate(Lifetime|Audience|Issuer)\s*=\s*false",
        "confidence": "HIGH",
        "examples": {"match": ["jwt.verify(t, k, { ignoreExpiration: true })"], "no_match": ["jwt.verify(t, k, { algorithms: ['HS256'] })"]},
    },
    {
        "id": "rest-jwt-no-aud-iss", "check_id": "REST-JWT-001", "type": "absence", "scope": "file",
        "title": "JWT verification without issuer/audience validation", "files": ["code"],
        "when": r"jwt\.verify\(|jwtVerify\(|jwt\.decode\(|Jwts\.parser|JWT\.require\(|jwt\.Parse\(|jwt\.ParseWithClaims\(|TokenValidationParameters",
        "missing": r"(?i)(audience|\baud\b|issuer|\biss\b|ValidateAudience|ValidateIssuer|withAudience|withIssuer)", "confidence": "LOW",
        "examples": {"match": ["const claims = jwt.verify(token, key, { algorithms: ['HS256'] });"], "no_match": ["jwt.verify(token, key, { algorithms: ['HS256'], audience: 'api', issuer: 'https://id' })"]},
    },
    {
        "id": "rest-api-key-query", "check_id": "REST-KEY-001", "title": "API key accepted from the query string",
        "files": ["code"],
        "pattern": r"(req\.query|request\.(args|GET|query_params)|URL\.Query\(\)|\$_GET|params\[:?|c\.Query\()\W{0,4}(\.\s*(get|Get)\(\s*)?['\"]?(api_?key|apikey|key|access_?key)\b",
        "confidence": "MEDIUM",
        "examples": {"match": ["const key = req.query.api_key;"], "no_match": ["const key = req.get('X-API-Key');"]},
    },
    # ------------------------------------------------------------------ METHOD / FLOW
    {
        "id": "rest-catch-all-method", "check_id": "REST-METHOD-001", "title": "Handler accepts every HTTP method",
        "files": ["code"],
        "pattern": r"\b(app|router)\.all\(\s*['\"`]/|@RequestMapping\(\s*(value\s*=\s*)?\"[^\"]*\"\s*\)|@RequestMapping\(\s*path\s*=\s*\"[^\"]*\"\s*\)|methods\s*=\s*\[\s*['\"]\*['\"]|\.Any\(\s*\"/|\[AcceptVerbs\(|\bmatch\s+['\"][^'\"]+['\"][^\n]*via:\s*:all",
        "confidence": "MEDIUM", "note": "Allow only the methods the endpoint implements; return 405 for the rest.",
        "examples": {"match": ["@RequestMapping(\"/orders\")\npublic List<Order> orders() {", "router.all('/api/items', handler)"], "no_match": ["@GetMapping(\"/orders\")"]},
    },
    {
        "id": "rest-method-override", "check_id": "REST-METHOD-001", "title": "HTTP method override enabled",
        "files": ["code", "config"],
        "pattern": r"methodOverride\(|X-HTTP-Method-Override|X-HTTP-Method\b|X-Method-Override|HiddenHttpMethodFilter|spring\.mvc\.hiddenmethod\.filter\.enabled\s*[=:]\s*true|UseHttpMethodOverride\(|Rack::MethodOverride",
        "confidence": "LOW", "note": "Method override lets a GET/POST be treated as PUT/DELETE; check it cannot bypass method-specific authorization.",
        "examples": {"match": ["app.use(methodOverride('X-HTTP-Method-Override'))"], "no_match": ["app.use(express.json())"]},
    },
    {
        "id": "rest-javaee-method-constraint", "check_id": "REST-METHOD-001", "title": "Security constraint limited to specific HTTP methods (verb tampering)",
        "files": ["config"], "path_includes": r"(?i)web\.xml$", "pattern": r"<http-method>\s*\w+\s*</http-method>",
        "confidence": "HIGH", "note": "Constraints that list methods leave every other method (HEAD, PUT, arbitrary verbs) unprotected.",
        "examples": {"match": ["<web-resource-collection><http-method>GET</http-method></web-resource-collection>"], "no_match": ["<web-resource-collection><url-pattern>/*</url-pattern></web-resource-collection>"]},
    },
    {
        "id": "rest-state-from-client", "check_id": "REST-FLOW-001", "title": "Workflow state taken from the request",
        "files": ["code"],
        "pattern": r"(?i)\b(status|state|step|stage|phase|workflow_?state|order_?status|payment_?status|approved|is_?paid|paid)\b['\"]?\s*[:=]\s*({{SRC}})",
        "confidence": "MEDIUM", "note": "Clients should request transitions; the server decides whether the current state allows them.",
        "examples": {"match": ["order.status = req.body.status;", "await Order.update({ paymentStatus: req.body.paymentStatus }, { where: { id } }); // payment_status"],
                     "no_match": ["order.status = nextStatus(order.status, 'pay');"]},
    },
    # ------------------------------------------------------------------ INPUT
    {
        "id": "rest-no-validation", "check_id": "REST-INPUT-001", "type": "absence", "scope": "file",
        "title": "Handlers read request input with no schema validation in the file", "files": ["code"],
        "path_includes": r"(?i)(route|controller|handler|view|api|endpoint|resource)",
        "when": r"\breq\.(body|query|params)\b|\brequest\.(json|form|args|data|get_json)\b|@RequestBody|c\.(Bind|ShouldBind)\w*\(|json\.NewDecoder\(\s*r\.Body",
        "missing": r"(?i)(zod|\bz\.(object|string|number|array)\(|safeParse|\.parse\(\s*(req|request)\.|joi|yup|ajv|valibot|superstruct|celebrate|express-validator|class-validator|ValidationPipe|pydantic|BaseModel|marshmallow|serializers?\.|Schema|validate|@Valid|@Validated|binding:\"|validator\.|FluentValidation|\[Required\]|DataAnnotations|typebox|t\.Object|cerberus|voluptuous|wtforms|Form\()",
        "confidence": "MEDIUM",
        "examples": {"match": ["router.post('/items', async (req, res) => { await Item.create(req.body); });"],
                     "no_match": ["const Item = z.object({ name: z.string().max(100) }).strict();\nrouter.post('/items', async (req, res) => { await Items.create(Item.parse(req.body)); });"]},
    },
    {
        "id": "rest-large-body-limit", "check_id": "REST-INPUT-002", "title": "Very large request body limit",
        "files": ["code", "config"],
        "pattern": r"(?i)(limit|max_?body_?size|maxBodySize|bodyLimit|MAX_CONTENT_LENGTH|client_max_body_size|max-http-request-header-size|maxRequestBodySize|max_request_size)\s*['\"]?\s*[:=]?\s*['\"]?\s*([1-9]\d{1,}\s*(mb|m\b|gb|g\b)|[1-9]\d{8,})",
        "confidence": "LOW",
        "examples": {"match": ["app.use(express.json({ limit: '50mb' }))", "client_max_body_size 100m;"], "no_match": ["app.use(express.json({ limit: '100kb' }))"]},
    },
    {
        "id": "rest-flask-no-max-content", "check_id": "REST-INPUT-002", "type": "absence", "scope": "project",
        "title": "Flask app without MAX_CONTENT_LENGTH", "files": ["py", "config"],
        "when": r"Flask\(__name__", "missing": r"MAX_CONTENT_LENGTH|MAX_FORM_MEMORY_SIZE", "confidence": "LOW",
        "examples": {"match": ["app = Flask(__name__)"], "no_match": ["app = Flask(__name__)\napp.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024"]},
    },
    {
        "id": "rest-go-no-max-bytes", "check_id": "REST-INPUT-002", "type": "absence", "scope": "file",
        "title": "Go handler decodes the body without http.MaxBytesReader", "files": ["go"],
        "when": r"json\.NewDecoder\(\s*\w+\.Body\)|io\.ReadAll\(\s*\w+\.Body\)|ioutil\.ReadAll\(\s*\w+\.Body\)",
        "missing": r"MaxBytesReader|LimitReader|BodyLimit", "confidence": "LOW",
        "examples": {"match": ["func h(w http.ResponseWriter, r *http.Request) { json.NewDecoder(r.Body).Decode(&v) }"],
                     "no_match": ["r.Body = http.MaxBytesReader(w, r.Body, 1<<20)\njson.NewDecoder(r.Body).Decode(&v)"]},
    },
    {
        "id": "rest-xxe-java-dotnet", "check_id": "REST-INPUT-003", "title": "XML parser created without disabling external entities",
        "files": ["java", "kt", "cs", "scala"],
        "pattern": r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|XMLReaderFactory)\.new\w*\(|new\s+SAXReader\(|new\s+SAXBuilder\(|new\s+XmlDocument\(|DtdProcessing\s*=\s*DtdProcessing\.Parse|XmlResolver\s*=\s*new\s+XmlUrlResolver",
        "not_near": {"pattern": r"(disallow-doctype-decl|FEATURE_SECURE_PROCESSING|external-general-entities|ACCESS_EXTERNAL_DTD|IS_SUPPORTING_EXTERNAL_ENTITIES|setExpandEntityReferences\(false\)|SUPPORT_DTD|DtdProcessing\.Prohibit|XmlResolver\s*=\s*null)", "lines": 8},
        "confidence": "MEDIUM",
        "examples": {"match": ["DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\nDocumentBuilder db = dbf.newDocumentBuilder();"],
                     "no_match": ["DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\ndbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);"]},
    },
    {
        "id": "rest-xxe-other", "check_id": "REST-INPUT-003", "title": "XML parsing with entity expansion enabled",
        "files": ["code"],
        "pattern": r"resolve_entities\s*=\s*True|no_network\s*=\s*False|\bnoent\s*:\s*true|LIBXML_NOENT|LIBXML_DTDLOAD|Nokogiri::XML\([^)]*\bnoent\b|libxml_disable_entity_loader\(\s*false",
        "confidence": "HIGH",
        "examples": {"match": ["doc = libxmljs.parseXml(body, { noent: true })"], "no_match": ["doc = defusedxml.ElementTree.fromstring(body)"]},
    },
    {
        "id": "rest-unsafe-deserialization", "check_id": "REST-INPUT-003", "title": "Unsafe deserialization of request data",
        "files": ["code"],
        "pattern": r"pickle\.loads?\(|yaml\.load\((?![^)]*Loader\s*=\s*(yaml\.)?(Safe|CSafe)Loader)|yaml\.unsafe_load\(|ObjectInputStream\(|XMLDecoder\(|\bunserialize\(|Marshal\.load\(|BinaryFormatter|TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto|Objects)|enableDefaultTyping\(|node-serialize",
        "near": {"pattern": "{{SRC}}|(?i:request|body|payload|input|upload)", "lines": 3}, "confidence": "HIGH",
        "examples": {"match": ["obj = pickle.loads(request.data)"], "no_match": ["obj = json.loads(request.data)"]},
    },
    # ------------------------------------------------------------------ CTYPE
    {
        "id": "rest-accept-echoed", "check_id": "REST-CTYPE-002", "title": "Accept header copied into the response Content-Type",
        "files": ["code"],
        "pattern": r"(?i)(content-type['\"]?\s*[,:]\s*|setHeader\(\s*['\"]content-type['\"]\s*,\s*|\.type\(\s*)(req\.(headers\.accept|headers\[['\"]accept['\"]\]|get\(['\"]accept['\"]\))|request\.headers\.get\(\s*['\"]accept['\"]|r\.Header\.Get\(\"Accept\"\))",
        "confidence": "HIGH",
        "examples": {"match": ["res.setHeader('Content-Type', req.headers.accept);"], "no_match": ["res.setHeader('Content-Type', 'application/json');"]},
    },
    {
        "id": "rest-json-as-text", "check_id": "REST-CTYPE-002", "title": "JSON sent without a JSON Content-Type",
        "files": ["code"],
        "pattern": r"res\.send\(\s*JSON\.stringify\(|return\s+json\.dumps\(|HttpResponse\(\s*json\.dumps\((?![^)]*content_type)|w\.Write\(\s*\w*[jJ]son\w*\s*\)|fmt\.Fprint\w*\(\s*w\s*,\s*string\(\s*\w*[jJ]son",
        "not_near": {"pattern": r"(?i)(application/json|\.type\(\s*['\"]json|content_type\s*=|mimetype\s*=|Content-Type)", "lines": 3},
        "confidence": "LOW",
        "examples": {"match": ["res.send(JSON.stringify(data));"], "no_match": ["res.json(data);"]},
    },
    # ------------------------------------------------------------------ MGMT / ERR / URL
    {
        "id": "rest-actuator-exposed", "check_id": "REST-MGMT-001", "title": "Management/debug endpoints exposed",
        "files": ["code", "config"],
        "pattern": r"management\.endpoints\.web\.exposure\.include\s*[=:]\s*['\"]?\*|management\.endpoint\.(env|heapdump|shutdown|threaddump|configprops)\.enabled\s*[=:]\s*true|_\s*\"net/http/pprof\"|expvar\.Handler|debug_toolbar|express-status-monitor|app\.use\(\s*['\"]/(admin|debug|metrics|_debug|internal)['\"]\s*,\s*(?!\w*(auth|Auth|require|protect|guard))|SilkyMiddleware|django_extensions|werkzeug\.debug",
        "confidence": "HIGH",
        "examples": {"match": ["management.endpoints.web.exposure.include=*", "import _ \"net/http/pprof\""], "no_match": ["management.endpoints.web.exposure.include=health,info"]},
    },
    {
        "id": "rest-stack-trace-response", "check_id": "REST-ERR-001", "title": "Stack trace or exception detail returned to clients",
        "files": ["code", "config"],
        "pattern": r"\.(json|send|end|write|render)\([^\n]*\b(err|error|e|ex)\.stack\b|traceback\.format_exc\(\)|printStackTrace\(\s*(response|resp)\.getWriter|server\.error\.include-(stacktrace|exception|message)\s*[=:]\s*(always|true)|debug\.Stack\(\)|DeveloperExceptionPage|customErrors\s+mode\s*=\s*\"Off\"|IncludeExceptionDetailInFaults\s*=\s*\"?true",
        "confidence": "HIGH",
        "examples": {"match": ["res.status(500).json({ error: err.message, stack: err.stack });", "server.error.include-stacktrace=always"], "no_match": ["res.status(500).json({ error: 'Internal error', requestId });"]},
    },
    {
        "id": "rest-debug-mode", "check_id": "REST-ERR-001", "title": "Framework debug mode enabled",
        "files": ["code", "config"],
        "pattern": r"(?m)^\s*DEBUG\s*=\s*True\b|\.run\([^)]*debug\s*=\s*True|FastAPI\([^)]*debug\s*=\s*True|app\.debug\s*=\s*True|APP_DEBUG\s*=\s*true|gin\.SetMode\(\s*gin\.DebugMode\s*\)|config\.consider_all_requests_local\s*=\s*true",
        "confidence": "MEDIUM", "note": "Confirm it is off in production configuration.",
        "examples": {"match": ["DEBUG = True", "app.run(debug=True)"], "no_match": ["DEBUG = os.environ.get('DEBUG') == '1'"]},
    },
    {
        "id": "rest-sensitive-in-query", "check_id": "REST-URL-001", "title": "Sensitive value read from the query string",
        "files": ["code"],
        "pattern": r"(req\.query|request\.(args|GET|query_params)|URL\.Query\(\)|\$_GET|params\[:?|c\.Query\(|@RequestParam\b[^)]*)\W{0,4}(\.\s*(get|Get)\(\s*)?['\"]?(password|passwd|pwd|token|access_?token|refresh_?token|secret|api_?key|apikey|ssn|card(_?number)?|otp|pin)\b",
        "confidence": "HIGH",
        "examples": {"match": ["const token = req.query.token;"], "no_match": ["const token = req.get('Authorization');"]},
    },
    # ------------------------------------------------------------------ HDR / CORS
    {
        "id": "rest-no-security-headers", "check_id": "REST-HDR-001", "type": "absence", "scope": "project",
        "title": "No security-header middleware or configuration found", "files": ["code", "config"],
        "when": "{{WEB_APP}}",
        "missing": r"(?i)(helmet|Strict-Transport-Security|X-Content-Type-Options|nosniff|SecurityMiddleware|SECURE_HSTS|secure_headers|secure\.Secure|Talisman|UseHsts|headers\(\)\s*\.|frameOptions|frame-ancestors|contentSecurityPolicy|@fastify/helmet|hono/secure-headers|secure-headers)",
        "confidence": "MEDIUM", "note": "Headers may be set by a reverse proxy; ask before confirming.",
        "examples": {"match": ["const app = express();\napp.use(express.json());"], "no_match": ["const app = express();\napp.use(helmet());"]},
    },
    {
        "id": "rest-x-powered-by", "check_id": "REST-HDR-001", "type": "absence", "scope": "file",
        "title": "Express app does not remove X-Powered-By", "files": ["js"],
        "when": r"express\(\)", "missing": r"x-powered-by|helmet", "confidence": "LOW",
        "examples": {"match": ["const app = express();"], "no_match": ["const app = express();\napp.disable('x-powered-by');"]},
    },
    {
        "id": "rest-no-cache-control", "check_id": "REST-HDR-001", "type": "absence", "scope": "project",
        "title": "API responses never set Cache-Control: no-store", "files": ["code", "config"],
        "when": "{{WEB_APP}}", "missing": r"(?i)no-store|nocache\(|noCache|never_cache|cache_control\(|CacheControl|ResponseCache\(\s*NoStore", "confidence": "LOW",
        "examples": {"match": ["app = FastAPI()"], "no_match": ["app = FastAPI()\nresponse.headers['Cache-Control'] = 'no-store'"]},
    },
    {
        "id": "rest-cors-credentials-wildcard", "check_id": "REST-CORS-001", "title": "CORS allows any origin together with credentials",
        "files": ["code", "config"],
        "pattern": r"(?i)origin\s*:\s*(true|['\"]\*['\"])[^\n]*credentials\s*:\s*true|credentials\s*:\s*true[^\n]*origin\s*:\s*(true|['\"]\*['\"])|allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\][^\n]*allow_credentials\s*=\s*True|allow_credentials\s*=\s*True[^\n]*allow_origins\s*=\s*\[\s*['\"]\*['\"]|supports_credentials\s*=\s*True|origin\s*:\s*\(\s*\w+\s*,\s*(cb|callback)\s*\)\s*=>\s*(cb|callback)\(\s*null\s*,\s*true\s*\)|AllowAllOrigins\s*:\s*true",
        "confidence": "HIGH",
        "examples": {"match": ["app.use(cors({ origin: true, credentials: true }))", "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)"],
                     "no_match": ["app.use(cors({ origin: ['https://app.example.com'], credentials: true }))"]},
    },
    {
        "id": "rest-cors-wildcard", "check_id": "REST-CORS-001", "title": "CORS open to any origin",
        "files": ["code", "config"],
        "pattern": r"(?i)app\.use\(\s*cors\(\s*\)\s*\)|Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*|CORS_(ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True|@CrossOrigin\(\s*(origins\s*=\s*)?\"\*\"|allowedOrigins\(\s*\"\*\"\s*\)|AllowAnyOrigin\(\)|allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]",
        "confidence": "MEDIUM", "note": "Acceptable for truly public, unauthenticated APIs; otherwise list origins.",
        "examples": {"match": ["app.use(cors())", "CORS_ALLOW_ALL_ORIGINS = True"], "no_match": ["app.use(cors({ origin: allowList }))"]},
    },
    # ------------------------------------------------------------------ AUDIT / STATUS / RATE
    {
        "id": "rest-no-auth-failure-logging", "check_id": "REST-AUDIT-001", "type": "absence", "scope": "project",
        "title": "Authentication/authorization failures are never logged", "files": ["code"],
        "when": r"(?i)(status\(\s*40[13]\s*\)|HTTPException\(\s*(status_code\s*=\s*)?40[13]|abort\(\s*40[13]|StatusUnauthorized|StatusForbidden|UnauthorizedException|ForbiddenException|ResponseStatusException\(\s*HttpStatus\.(UNAUTHORIZED|FORBIDDEN))",
        "missing": r"(?i)(audit|security_?log|securityLogger|log\w*\.(warn|warning|info|error)\([^)\n]*(fail|denied|invalid|unauthori|forbidden))",
        "confidence": "LOW",
        "examples": {"match": ["if (!ok) return res.status(401).json({ error: 'unauthorized' });"],
                     "no_match": ["if (!ok) { logger.warn('auth failed for %s', id); return res.status(401).end(); }"]},
    },
    {
        "id": "rest-error-with-200", "check_id": "REST-STATUS-001", "title": "Error returned with HTTP 200",
        "files": ["code"],
        "pattern": r"res\.status\(\s*200\s*\)\.(json|send)\(\s*\{\s*['\"]?(error|err|success\s*:\s*false)|return\s+[^\n]*\{\s*['\"](error|err)['\"][^\n]*\}\s*,\s*200\b|res\.json\(\s*\{\s*(success|ok)\s*:\s*false",
        "confidence": "LOW",
        "examples": {"match": ["return res.status(200).json({ error: 'not found' });"], "no_match": ["return res.status(404).json({ error: 'not found' });"]},
    },
    {
        "id": "rest-no-rate-limit", "check_id": "REST-RATE-001", "type": "absence", "scope": "project",
        "title": "No rate limiting found anywhere in the API", "files": ["code", "config"],
        "when": "{{WEB_APP}}", "missing": "{{RATE_LIMIT}}|(?i:429|TooManyRequests)", "confidence": "MEDIUM",
        "note": "Gateways or proxies may enforce limits outside the repo; ask before confirming.",
        "examples": {"match": ["const app = express();"], "no_match": ["const app = express();\napp.use(rateLimit({ windowMs: 60e3, max: 100 }));"]},
    },
]

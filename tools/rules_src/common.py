"""Macros shared by several skills' rules. Referenced inside patterns as {{NAME}}."""

MACROS = {
    # Request input, per language family. Deliberately broad: a hit means "look here", not "vulnerable".
    "SRC_JS": r"\breq\.(query|body|params|headers|cookies)|\brequest\.(query|body|params)|\bctx\.(query|params|request\.body)|\bevent\.(body|queryStringParameters|pathParameters)|searchParams\.get\(",
    "SRC_PY": r"\brequest\.(args|form|json|values|data|GET|POST|query_params|get_json|files|headers|cookies|path_params|view_args)|\bself\.request\b",
    "SRC_JAVA": r"@RequestParam|@PathVariable|@RequestBody|\.getParameter\(|\.getHeader\(|\.getQueryString\(",
    "SRC_GO": r"\.URL\.Query\(\)|\.FormValue\(|\.PostFormValue\(|\bc\.(Query|Param|PostForm|DefaultQuery|GetHeader)\(|mux\.Vars\(|chi\.URLParam\(",
    "SRC_PHP": r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|\$request->(input|get|query|post)\(",
    "SRC_RB": r"\bparams\[|\brequest\.(params|body|headers)",
    "SRC_CS": r"\bRequest\.(Query|Form|Headers|Cookies)\b|\[From(Query|Body|Route|Form|Header)\]",
    "SRC": "{{SRC_JS}}|{{SRC_PY}}|{{SRC_JAVA}}|{{SRC_GO}}|{{SRC_PHP}}|{{SRC_RB}}|{{SRC_CS}}",
    # Non-cryptographic randomness.
    "WEAK_RANDOM": r"Math\.random\(|\brandom\.(random|randint|randrange|choice|choices|getrandbits|sample)\(|\bnew\s+Random\(|\bmt_rand\(|\brand\(\)|\buniqid\(|\buuid\.v1\(|\buuid1\(\)|\bRandom\.(nextInt|nextLong)\(|\bRandom::rand",
    # Things that make a value a secret/token.
    "TOKENISH": r"(?i:token|secret|nonce|salt|api_?key|apikey|otp|csrf|session_?id|reset|verify|verification|invite|magic|code|password)",
    # Rate-limiting / lockout libraries and idioms across stacks.
    "RATE_LIMIT": r"(?i:rate.?limit|throttl|slow.?down|express-brute|limiter|bucket4j|@Throttle|django_ratelimit|flask_limiter|slowapi|rack.attack|tollbooth|x/time/rate|ulule/limiter|AspNetCoreRateLimit|AddRateLimiter|lockout|failed_?(login_?)?attempts|login_?attempts|max_?attempts|brute)",
    # Logging calls.
    "LOG_CALL": r"(console\.(log|info|debug|warn|error)|\blogger?\.(info|debug|log|warn|warning|error|trace)|\blog\.(Print\w*|Info\w*|Debug\w*|Warn\w*|Error\w*|info|debug)|\bprint\(|System\.out\.print\w*|\bputs\b|\bLog\.(d|i|w|e)|\bfmt\.Print\w*)\s*\(?",
    # Secret-ish identifier names.
    "SECRET_NAME": r"(?i:[A-Za-z_]*(secret|token|passw(or)?d|pwd|api_?key|apikey|access_?key|private_?key|client_?secret|auth_?key|signing_?key|encryption_?key|credentials?)[A-Za-z_0-9]*)",
    # Values that are obviously placeholders.
    "PLACEHOLDER": r"(?i:\$\{|\{\{|<|%\(|process\.env|os\.environ|getenv|changeme|change_me|change-me|example|placeholder|your[_-]|xxx|dummy|sample|todo|redacted|\*\*\*|test)",
}

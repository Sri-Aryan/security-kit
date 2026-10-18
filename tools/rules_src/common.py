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
    # Secret-ish identifier names. Non-capturing: rules refer to their own groups by number.
    "SECRET_NAME": r"(?i:[A-Za-z_]*(?:secret|token|passw(?:or)?d|pwd|api_?key|apikey|access_?key|private_?key|client_?secret|auth_?key|signing_?key|encryption_?key|credentials?)[A-Za-z_0-9]*)",
    # LLM call sites (any provider / framework).
    "LLM_CALL": r"chat\.completions\.create|\bresponses\.create\(|messages\.create\(|ChatCompletion\.create|\bgenerateText\(|\bstreamText\(|\bgenerateObject\(|\bstreamObject\(|\.a?invoke\(|ChatOpenAI|ChatAnthropic|AzureChatOpenAI|ChatGoogleGenerativeAI|\bllm\.(predict|call|complete|chat|stream)\(|\bcompletion\(|\bacompletion\(|GenerativeModel\(|generate_content\(|ollama\.(chat|generate)\(|invoke_model\(|\.converse\(|createChatCompletion|\.chat\.send|runAgent|Agent\(|AgentExecutor|new\s+Anthropic\(|new\s+OpenAI\(|OpenAI\(\)|Anthropic\(\)",
    # Variables that usually hold model output.
    "MODEL_OUT": r"(?i:\b(completion|response|resp|output|result|answer|generated|reply|llm_?\w*|model_?output|ai_?\w*|assistant_?\w*|message\.content|choices\[0\]|content\[0\]|\.text\b|\.content\b|tool_?(args|input|call)\w*|sql_?query|generated_?\w*))",
    # Tool / function definitions for models and MCP servers.
    "TOOL_DEF": r"@tool\b|\btool\(\s*\{|\btools\s*[:=]\s*\[|function_declarations|['\"]type['\"]\s*:\s*['\"]function['\"]|DynamicTool|StructuredTool|server\.tool\(|\.registerTool\(|@mcp\.tool|FastMCP\(|McpServer\(|\bdefineTool\(|\bcreateTool\(|@function_tool|FunctionTool|\.bind_tools\(|tool_choice",
    "DANGEROUS_OP": r"(?i:\bexec\w*\(|spawn\(|subprocess|os\.system|child_process|\bshell\b|\brm\s|unlink|\bdelete\w*\(|DROP\s|transfer|payment|charge|refund|send_?e?mail|sendMail|post_?message|slack|write_?file|writeFile|\bfetch\(|requests\.(post|put|delete)|axios\.(post|put|delete)|\.execute\(|\.query\()",
    "APPROVAL": r"(?i:confirm|approv|human|requires_?approval|needsApproval|interrupt|HumanInTheLoop|human_in_the_loop|ask_?user|permission|consent|review)",
    # Reading the request Host header (link poisoning).
    "HOST_HEADER": r"req\.(headers\.host\b|get\(\s*['\"]host['\"]\)|hostname\b)|req\.headers\[['\"]host['\"]\]|request\.(host\b|get_host\(\)|host_url|url_root|base_url|META\[['\"]HTTP_HOST['\"]\])|\br\.Host\b|getServerName\(\)|Request\.Host\b|getHeader\(\s*\"[Hh]ost\"\s*\)|\$_SERVER\[['\"]HTTP_HOST['\"]\]|request\.host_with_port|X-Forwarded-Host",
    # Server-side HTTP clients.
    "FETCH": r"\bfetch\(|\baxios(\.(get|post|put|request|head))?\(|\bgot(\.\w+)?\(|\bneedle\(|\bsuperagent|\brequest(\.get)?\(|https?\.(get|request)\(|undici\.(request|fetch)|requests\.(get|post|put|head|request)\(|httpx\.(get|post|request|stream|AsyncClient|Client)|urllib\.request\.urlopen\(|\burlopen\(|aiohttp\.ClientSession|http\.(Get|Post|Head|NewRequest)\(|\bresty\.|RestTemplate\b|WebClient\b|HttpClient\b|HttpURLConnection|new\s+URL\([^)]*\)\.openConnection|OkHttpClient|Net::HTTP|open-uri|URI\.open|Faraday|HTTParty|curl_exec|file_get_contents\(\s*\$|Guzzle",
    # Values that are obviously placeholders, references, URLs or paths rather than secrets.
    "PLACEHOLDER": r"(?i:\$\{|\{\{|<|%\(|process\.env|os\.environ|getenv|changeme|change_me|change-me|example|placeholder|your[_-]|xxx|dummy|sample|todo|redacted|\*\*\*|test|fake|invalid|wrong|probe|https?://|/|\./)",
}

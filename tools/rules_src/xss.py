"""sk-xss rules."""

SKILL = "sk-xss"

MACROS = {
    "DOM_SRC": r"location\.(hash|search|href|pathname)|document\.(URL|documentURI|referrer|baseURI|cookie)|window\.name|URLSearchParams|searchParams\.get|event\.data|e\.data|msg\.data|localStorage\.getItem|sessionStorage\.getItem|useSearchParams|router\.query|\$route\.(query|params)|useParams\(",
    "SANITIZED": r"(?i:DOMPurify|sanitize|sanitizeHtml|sanitize-html|xss\(|escape|encode|bleach|nh3|textContent|innerText|htmlspecialchars|Encoder\.|HtmlEncoder|PolicyFactory)",
}

RULES = [
    {
        "id": "xss-dom-html-sink", "check_id": "XSS-SINK-001", "title": "Raw HTML DOM sink", "files": ["js", "web"],
        "pattern": r"\.(innerHTML|outerHTML)\s*\+?=(?!=)|\.insertAdjacentHTML\(|document\.write(ln)?\(|\.html\(\s*[^)\s]|\$\(\s*['\"`]?\s*<[^)]*\+|\.(append|prepend|after|before|replaceWith)\(\s*['\"`]\s*<[^)]*(\+|\$\{)|createContextualFragment\(|DOMParser\(\)\.parseFromString\(",
        "not_near": {"pattern": "{{SANITIZED}}", "lines": 1}, "confidence": "MEDIUM",
        "examples": {"match": ["el.innerHTML = `<b>${name}</b>`;", "$('#out').html(data.message);"], "no_match": ["el.textContent = name;", "el.innerHTML = DOMPurify.sanitize(html);"]},
    },
    {
        "id": "xss-framework-bypass", "check_id": "XSS-SINK-002", "title": "Framework auto-escaping bypassed", "files": ["js", "web", "py", "rb", "php", "java", "cs"],
        "pattern": r"dangerouslySetInnerHTML|\bv-html\b|\{@html\s|\[innerHTML\]\s*=|bypassSecurityTrust(Html|Script|Url|ResourceUrl|Style)\(|\|\s*safe\b|\bmark_safe\(|\bMarkup\(|\.html_safe\b|<%==|\braw\(|<%-|\{\{\{|\{!!|@Html\.Raw\(|th:utext=|\bescape\s*=\s*['\"]?false|autoescape\s+off|\|\s*raw\b|\bHtmlString\(|new\s+SafeString\(",
        "not_near": {"pattern": "{{SANITIZED}}", "lines": 1}, "confidence": "MEDIUM",
        "note": "Fine for trusted, developer-authored HTML; a finding when any part comes from users or external data.",
        "examples": {"match": ["<div dangerouslySetInnerHTML={{ __html: comment.body }} />", "<p>{{ bio|safe }}</p>"], "no_match": ["<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.body) }} />", "<p>{{ bio }}</p>"]},
    },
    {
        "id": "xss-autoescape-off", "check_id": "XSS-TPL-001", "title": "Template auto-escaping disabled", "files": ["code", "config"],
        "pattern": r"autoescape\s*=\s*False|autoescape\s*:\s*false|['\"]autoescape['\"]\s*:\s*False|Environment\((?![^)]*autoescape)|noEscape\s*:\s*true|escape\s*:\s*false|Handlebars\.compile\([^)]*noEscape|setAutoEscape\(\s*false|\{%\s*autoescape\s+(false|off)\s*%\}",
        "confidence": "HIGH", "note": "jinja2.Environment() defaults to autoescape off outside Flask; pass autoescape=select_autoescape().",
        "examples": {"match": ["env = jinja2.Environment(loader=FileSystemLoader('t'))", "{% autoescape false %}"], "no_match": ["env = jinja2.Environment(loader=l, autoescape=select_autoescape())"]},
    },
    {
        "id": "xss-dom-source-to-sink", "check_id": "XSS-DOM-001", "title": "DOM source flows into an HTML/JS sink", "files": ["js", "web"],
        "pattern": r"(\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write|\.html\(|eval\(|new\s+Function\(|setTimeout\(|location\s*=|location\.href\s*=|\.src\s*=|\.href\s*=)[^;\n]*({{DOM_SRC}})",
        "not_near": {"pattern": "{{SANITIZED}}", "lines": 1}, "confidence": "HIGH",
        "examples": {"match": ["document.getElementById('q').innerHTML = new URLSearchParams(location.search).get('q');"], "no_match": ["document.getElementById('q').textContent = new URLSearchParams(location.search).get('q');"]},
    },
    {
        "id": "xss-js-url-href", "check_id": "XSS-URL-001", "title": "User-controlled URL rendered into href/src", "files": ["js", "web"],
        "pattern": r"(href|src|action|formAction|formaction|xlink:href)\s*=\s*\{\s*(?!['\"`]/)[\w.?]*(url|link|href|website|homepage|redirect|src|avatar|image)\w*\s*\}|(href|src)=[\"']\{\{\s*[\w.]*(url|link|website|homepage)\w*\s*\}\}[\"']|:(href|src)=[\"'][\w.]*(url|link|website|homepage)\w*[\"']",
        "not_near": {"pattern": r"(?i)(safeUrl|sanitizeUrl|isSafeUrl|https?:|startsWith\(['\"]http|new URL\(|protocol\s*===|allowedProtocols|@braintree/sanitize-url)", "lines": 3},
        "confidence": "MEDIUM", "note": "`javascript:alert(1)` in a profile URL executes on click; allow only http(s).",
        "examples": {"match": ["<a href={user.website}>Website</a>"], "no_match": ["<a href={sanitizeUrl(user.website)}>Website</a>"]},
    },
    {
        "id": "xss-script-block-interp", "check_id": "XSS-JS-001", "title": "Data interpolated into a <script> block or inline handler", "files": ["web"],
        "pattern": r"<script[^>]*>[^<]*(\{\{(?![^}]*\|\s*(tojson|json_script|escapejs))[^}]*\}\}|<%=\s*(?!json|raw\s+json|j\()[^%]*%>|\$\{[^}]+\}|@\w+(?!\.Json)|<\?=\s*\$)|\bon\w+\s*=\s*\"[^\"]*(\{\{|<%=|\$\{)|\bon\w+\s*=\s*'[^']*(\{\{|<%=|\$\{)",
        "confidence": "MEDIUM", "note": "Use json_script / tojson / JSON serialization with HTML-safe escaping, or data attributes.",
        "examples": {"match": ["<script>var user = '{{ user.name }}';</script>", "<button onclick=\"go('{{ next }}')\">"], "no_match": ["<script>var user = {{ user|tojson }};</script>"]},
    },
    {
        "id": "xss-json-in-script", "check_id": "XSS-JS-001", "title": "JSON.stringify output written into a script tag", "files": ["js", "web"],
        "pattern": r"<script[^>]*>[^<]*\$\{\s*JSON\.stringify\(|__INITIAL_STATE__\s*=\s*\$\{\s*JSON\.stringify|window\.\w+\s*=\s*['\"`]?\s*\+\s*JSON\.stringify\(",
        "not_near": {"pattern": r"(serialize-javascript|serialize\(|replace\(\s*/<\/?|\\\\u003c|htmlEscapeJson|escapeJson)", "lines": 2},
        "confidence": "MEDIUM", "note": "JSON.stringify does not escape `</script>`; use serialize-javascript or escape `<`.",
        "examples": {"match": ["res.send(`<script>window.__INITIAL_STATE__ = ${JSON.stringify(state)}</script>`)"], "no_match": ["res.send(`<script>window.__INITIAL_STATE__ = ${serialize(state)}</script>`)"]},
    },
    {
        "id": "xss-string-eval", "check_id": "XSS-EVAL-001", "title": "String evaluated as code in the browser", "files": ["js", "web"],
        "pattern": r"\beval\(\s*[^)'\"`\s]|new\s+Function\(\s*[^)]*[a-zA-Z_$]|\bset(Timeout|Interval)\(\s*(['\"`][^'\"`]*['\"`]\s*\+|`[^`]*\$\{|[a-zA-Z_$][\w.]*\s*[,)])(?![^)]*=>)",
        "confidence": "MEDIUM",
        "examples": {"match": ["setTimeout('update(' + id + ')', 100);", "const fn = new Function('x', body);"], "no_match": ["setTimeout(() => update(id), 100);"]},
    },
    {
        "id": "xss-regex-sanitizer", "check_id": "XSS-SANITIZE-001", "title": "Home-made regex HTML sanitizer", "files": ["code"],
        "pattern": r"\.replace\(\s*/<\s*\/?\s*script[^/]*/[gimsuy]*|\.replace\(\s*/<\[\^>\]\*>/[gimsuy]*|re\.sub\(\s*r?['\"]<[^'\"]*script|strip_tags\(|\.replace\(\s*/on\\w\+=",
        "confidence": "MEDIUM", "note": "Regex sanitizers are bypassable; use DOMPurify / sanitize-html / nh3 / OWASP Java HTML Sanitizer.",
        "examples": {"match": ["const clean = html.replace(/<script[^>]*>.*?<\\/script>/gi, '');"], "no_match": ["const clean = DOMPurify.sanitize(html);"]},
    },
    {
        "id": "xss-markdown-raw-html", "check_id": "XSS-MD-001", "title": "Markdown rendered with raw HTML enabled", "files": ["js", "py", "rb", "web"],
        "pattern": r"html\s*:\s*true|rehypeRaw|rehype-raw|allowDangerousHtml\s*:\s*true|skipHtml\s*:\s*false|sanitize\s*:\s*false|markdown\.markdown\([^)]*\)\s*\|?\s*safe|Redcarpet::Render::HTML\.new\((?![^)]*escape_html)|safe_mode\s*=\s*False|unsafe\s*:\s*true",
        "near": {"pattern": r"(?i)(markdown|marked|remark|rehype|markdown-it|MarkdownIt|showdown|redcarpet|commonmark)", "lines": 4},
        "not_near": {"pattern": "{{SANITIZED}}|rehype-sanitize|rehypeSanitize", "lines": 4}, "confidence": "MEDIUM",
        "examples": {"match": ["const md = new MarkdownIt({ html: true });"], "no_match": ["const md = new MarkdownIt({ html: false });"]},
    },
    {
        "id": "xss-message-no-origin", "check_id": "XSS-POSTMSG-001", "title": "message listener without an origin check", "files": ["js", "web"],
        "pattern": r"addEventListener\(\s*['\"]message['\"]|\bonmessage\s*=",
        "not_near": {"pattern": r"\.origin\b", "lines": 6}, "confidence": "MEDIUM",
        "examples": {"match": ["window.addEventListener('message', (e) => { render(e.data.html); });"], "no_match": ["window.addEventListener('message', (e) => { if (e.origin !== APP_ORIGIN) return; render(e.data); });"]},
    },
    {
        "id": "xss-postmessage-star", "check_id": "XSS-POSTMSG-001", "title": "postMessage to any origin ('*')", "files": ["js", "web"],
        "pattern": r"\.postMessage\([^)]*,\s*['\"]\*['\"]\s*\)", "confidence": "LOW",
        "examples": {"match": ["parent.postMessage({ token }, '*');"], "no_match": ["parent.postMessage({ ok: true }, 'https://app.example.com');"]},
    },
    {
        "id": "xss-reflected-html-response", "check_id": "XSS-RESP-001", "title": "Request input written into an HTML response", "files": ["code"],
        "pattern": r"(res\.send|res\.write|res\.end|response\.write|HttpResponse|make_response|w\.Write|fmt\.Fprint\w*\(\s*w|echo|print|Response\.Write|render\s+(html|inline|plain))\s*\(?\s*[^;\n]*(`[^`]*\$\{\s*({{SRC}})|['\"][^'\"]*<[^'\"]*['\"]\s*\+\s*({{SRC}})|f['\"][^'\"]*<[^'\"]*\{\s*({{SRC_PY}})|\$_(GET|POST|REQUEST)\[)",
        "confidence": "HIGH",
        "examples": {"match": ["res.send(`<h1>Results for ${req.query.q}</h1>`);", "echo '<p>' . $_GET['name'];"], "no_match": ["res.render('results', { q: req.query.q });"]},
    },
    {
        "id": "xss-jsonp-callback", "check_id": "XSS-RESP-001", "title": "JSONP callback name from the request", "files": ["code"],
        "pattern": r"(?i)(callback|jsonp|cb)\w*['\"]?\]?\s*\+\s*['\"]\(|res\.jsonp\(|\$\{\s*({{SRC}})[^}]*\}\s*\(|request\.args\.get\(\s*['\"](callback|jsonp)['\"]",
        "confidence": "MEDIUM", "examples": {"match": ["res.type('js').send(req.query.callback + '(' + JSON.stringify(data) + ')');"], "no_match": ["res.json(data);"]},
    },
    {
        "id": "xss-svg-html-upload-inline", "check_id": "XSS-UPLOAD-001", "title": "Uploads served inline from the app origin (SVG/HTML)", "files": ["code", "config"],
        "pattern": r"(?i)express\.static\(\s*['\"`]?[^)]*uploads?|app\.use\(\s*['\"]/uploads?['\"]\s*,\s*express\.static|MEDIA_URL\s*=\s*['\"]/media|location\s+/uploads?\b|send_from_directory\(\s*[^,]*UPLOAD",
        "confidence": "LOW", "note": "Uploaded SVG/HTML runs script on your origin; serve uploads from a separate domain or with Content-Disposition: attachment.",
        "examples": {"match": ["app.use('/uploads', express.static('uploads'));"], "no_match": ["app.use('/static', express.static('public'));"]},
    },
    {
        "id": "xss-no-csp", "check_id": "XSS-CSP-001", "type": "absence", "scope": "project",
        "title": "No Content Security Policy configured anywhere", "files": ["code", "config", "web"],
        "when": r"(?i)(<html|render\(|res\.render|render_template|TemplateResponse|@Controller|ReactDOM|createRoot\(|next\.config|nuxt\.config)",
        "missing": r"(?i)(Content-Security-Policy|contentSecurityPolicy|csp\s*[:=(]|helmet\(|CSP_|SECURE_CSP|ContentSecurityPolicy|csp_nonce|http-equiv=[\"']Content-Security-Policy)",
        "confidence": "MEDIUM", "note": "CSP may be set by a proxy/CDN; ask before confirming.",
        "examples": {"match": ["res.render('index', data);"], "no_match": ["app.use(helmet({ contentSecurityPolicy: { directives } }));\nres.render('index', data);"]},
    },
    {
        "id": "xss-weak-csp", "check_id": "XSS-CSP-001", "title": "Weak CSP (unsafe-inline / unsafe-eval / wildcard script sources)", "files": ["code", "config", "web"],
        "pattern": r"(?i)(script-src|default-src|scriptSrc|defaultSrc)[^;\n]*('unsafe-inline'|'unsafe-eval'|\"unsafe-inline\"|\"unsafe-eval\"|\s\*[\s;'\"\]]|https:\s*[;'\"\]]|data:)",
        "confidence": "MEDIUM", "note": "Prefer nonce- or hash-based script-src with 'strict-dynamic'.",
        "examples": {"match": ["Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'"], "no_match": ["Content-Security-Policy: script-src 'nonce-r4nd0m' 'strict-dynamic'; object-src 'none'; base-uri 'none'"]},
    },
    {
        "id": "xss-cookie-not-httponly", "check_id": "XSS-COOKIE-001", "title": "Session cookie readable by JavaScript", "files": ["code", "config"],
        "pattern": r"(?i)httpOnly['\"]?\s*[:=]\s*(false|False)|SESSION_COOKIE_HTTPONLY\s*=\s*False|setHttpOnly\(\s*false|document\.cookie\s*=\s*[^;\n]*(session|token|auth|jwt)",
        "confidence": "MEDIUM",
        "examples": {"match": ["document.cookie = 'session=' + token;"], "no_match": ["res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' });"]},
    },
]

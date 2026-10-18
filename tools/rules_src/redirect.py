"""sk-redirect rules."""

SKILL = "sk-redirect"

MACROS = {
    "REDIR_PARAM": r"(?i:next|return_?to|returnTo|return_?url|returnUrl|redirect\w*|redir|continue|goto|url|target|dest\w*|callback\w*|from|back|forward|ref)",
    "REDIR_SAFE": r"(?i:is_?safe_?url|url_has_allowed_host_and_scheme|isSafeRedirect|safeRedirect|validateRedirect|isRelative|allow_?list|allowlist|whitelist|ALLOWED_\w*HOSTS|sameOrigin|new URL\([^)]*\)\.(origin|host)|UrlHelper\.IsLocalUrl|Url\.IsLocalUrl|LocalRedirect|redirect_to\s+url_for|safe_redirect|startsWith\(\s*['\"]/['\"]\s*\)\s*&&\s*!)",
}

RULES = [
    {
        "id": "redir-server-from-request", "check_id": "REDIR-OPEN-001", "title": "Redirect target taken from the request", "files": ["code"],
        "pattern": r"(res\.redirect|redirect|Redirect|RedirectResponse|HttpResponseRedirect|redirect_to|sendRedirect|header\(\s*['\"]Location:|http\.Redirect|c\.Redirect|ctx\.redirect|Response\.Redirect|RedirectToAction)\s*\(?\s*[^)\n]*({{SRC}})",
        "not_near": {"pattern": "{{REDIR_SAFE}}", "lines": 4}, "confidence": "MEDIUM",
        "examples": {"match": ["res.redirect(req.query.next || '/');", "return redirect(request.args.get('next'))", "header('Location: ' . $_GET['url']);"],
                     "no_match": ["return redirect(next_url if url_has_allowed_host_and_scheme(next_url, allowed_hosts=ALLOWED) else '/')"]},
    },
    {
        "id": "redir-weak-validation", "check_id": "REDIR-VALID-001", "title": "Redirect target validated with a bypassable string check", "files": ["code"],
        "pattern": r"(?i)\b\w*({{REDIR_PARAM}})\w*\s*\.\s*(startsWith|startswith|includes|indexOf|contains|endsWith|endswith)\(\s*['\"`](/|https?://)",
        "not_near": {"pattern": r"(//|\\\\|new URL\(|urlparse|url\.Parse|URI\.parse|parse_url)", "lines": 2}, "confidence": "MEDIUM",
        "note": "`//evil.com` starts with `/`; `https://trusted.com.evil.com` starts with `https://trusted.com`; parse and compare the host.",
        "examples": {"match": ["if (next.startsWith('/')) return res.redirect(next);"], "no_match": ["const u = new URL(next, APP_URL); if (u.origin === APP_URL) return res.redirect(u.pathname + u.search);"]},
    },
    {
        "id": "redir-auth-flow", "check_id": "REDIR-AUTH-001", "title": "Login/logout/SSO return URL from the request", "files": ["code"],
        "pattern": r"(?i)(redirect\w*|location|return\w*|next)\s*[:=(]\s*[^)\n]*({{SRC}})[^)\n]*",
        "near": {"pattern": r"(?i)(login|logout|signin|sign_in|signout|sso|oauth|callback|auth)", "lines": 6},
        "not_near": {"pattern": "{{REDIR_SAFE}}", "lines": 6}, "confidence": "MEDIUM",
        "examples": {"match": ["router.get('/logout', (req, res) => { req.session.destroy(); res.redirect(req.query.returnTo); });"],
                     "no_match": ["router.get('/logout', (req, res) => { req.session.destroy(); res.redirect(safeRedirect(req.query.returnTo)); });"]},
    },
    {
        "id": "redir-forward-from-request", "check_id": "REDIR-FWD-001", "title": "Server-side forward / X-Accel-Redirect driven by input", "files": ["code"],
        "pattern": r"(getRequestDispatcher\(|\.forward\(|X-Accel-Redirect|X-Sendfile|X-LiteSpeed-Location|Server\.Transfer\(|forward:\s*['\"]?\s*\+|render_to_response\()[^\n]*({{SRC}})",
        "confidence": "HIGH",
        "examples": {"match": ["request.getRequestDispatcher(request.getParameter(\"page\")).forward(request, response);", "res.setHeader('X-Accel-Redirect', '/protected/' + req.query.file);"],
                     "no_match": ["request.getRequestDispatcher(\"/WEB-INF/views/home.jsp\").forward(request, response);"]},
    },
    {
        "id": "redir-client-location", "check_id": "REDIR-CLIENT-001", "title": "Client-side navigation to a URL parameter", "files": ["js", "web"],
        "pattern": r"(location\.(href|assign|replace)|window\.location|document\.location|window\.open|router\.(push|replace)|navigate)\s*[=(]\s*[^;\n]*(searchParams\.get|URLSearchParams|location\.(search|hash)|query\.|useSearchParams|\$route\.query)",
        "not_near": {"pattern": "{{REDIR_SAFE}}|(?i:startsWith\\(['\"]/['\"]\\)\\s*&&)", "lines": 3}, "confidence": "MEDIUM",
        "examples": {"match": ["window.location.href = new URLSearchParams(location.search).get('next');"], "no_match": ["const n = new URLSearchParams(location.search).get('next');\nif (isSafeRedirect(n)) window.location.href = n;"]},
    },
    {
        "id": "redir-meta-refresh", "check_id": "REDIR-META-001", "title": "Meta refresh / Refresh header with a dynamic URL", "files": ["web", "code"],
        "pattern": r"(?i)http-equiv=[\"']refresh[\"'][^>]*url=\s*(\{\{|<%=|\$\{|<\?=|@)|setHeader\(\s*['\"]Refresh['\"][^)]*(\+|\$\{)|header\(\s*['\"]Refresh:[^)]*\.\s*\$",
        "confidence": "MEDIUM",
        "examples": {"match": ["<meta http-equiv=\"refresh\" content=\"0;url={{ next }}\">"], "no_match": ["<meta http-equiv=\"refresh\" content=\"0;url=/home\">"]},
    },
    {
        "id": "redir-referer", "check_id": "REDIR-REFERER-001", "title": "Redirect back to the Referer header", "files": ["code"],
        "pattern": r"(?i)(redirect|Redirect|redirect_to|sendRedirect)\s*\(?\s*[^)\n]*(referer|referrer|HTTP_REFERER|:back\b|redirect_back|request\.META\.get\(\s*['\"]HTTP_REFERER)",
        "not_near": {"pattern": "{{REDIR_SAFE}}|fallback_location", "lines": 2}, "confidence": "LOW",
        "examples": {"match": ["res.redirect(req.get('Referer'));"], "no_match": ["res.redirect('/dashboard');"]},
    },
    {
        "id": "redir-url-shortener", "check_id": "REDIR-EXTERNAL-001", "title": "Generic redirect endpoint (/redirect, /go, /out, /link)", "files": ["code"],
        "pattern": r"['\"`][^'\"`\s]*/(redirect|go|out|link|r|away|external|leave|jump|bounce)['\"`]\s*,",
        "near": {"pattern": r"(?i)redirect", "lines": 4}, "confidence": "LOW",
        "examples": {"match": ["app.get('/out', (req, res) => res.redirect(req.query.u));"], "no_match": ["app.get('/home', (req, res) => res.render('home'));"]},
    },
]

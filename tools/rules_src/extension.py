"""sk-extension rules: manifest permissions/CSP/externally_connectable/WAR/update_url, remote code, messaging, DOM."""

SKILL = "sk-extension"

MANIFEST = r"(?i)(^|/)manifest(\.v\d)?\.json$|(^|/)(wxt\.config|plasmo\.config)\.[jt]s$"
EXT_CTX = r"chrome\.|browser\.(runtime|tabs|storage)|manifest_version"

RULES = [
    {
        "id": "ext-broad-host-permissions", "check_id": "EXT-PERM-001", "title": "Extension requests access to all sites", "files": ["config", "js"], "path_includes": MANIFEST,
        "pattern": r"['\"](<all_urls>|\*://\*/\*|https?://\*/\*|\*://\*\.?[^/'\"]*/\*)['\"]", "near": {"pattern": r"(?i)permissions|host_permissions|matches", "lines": 8},
        "file_requires": r"manifest_version|host_permissions|permissions", "confidence": "MEDIUM",
        "examples": {"match": ["{ \"manifest_version\": 3, \"host_permissions\": [\"<all_urls>\"] }"], "no_match": ["{ \"manifest_version\": 3, \"host_permissions\": [\"https://app.acme.com/*\"] }"]},
    },
    {
        "id": "ext-sensitive-permissions", "check_id": "EXT-PERM-001", "title": "Sensitive extension permission requested", "files": ["config", "js"], "path_includes": MANIFEST,
        "pattern": r"['\"](cookies|webRequest|webRequestBlocking|debugger|nativeMessaging|management|history|proxy|privacy|clipboardRead|downloads|browsingData|declarativeNetRequestWithHostAccess|webNavigation)['\"]",
        "near": {"pattern": r"\"permissions\"\s*:", "lines": 12}, "not_near": {"pattern": r"\"optional_permissions\"\s*:", "lines": 2},
        "file_requires": r"manifest_version", "confidence": "LOW", "note": "Confirm each one is needed; prefer optional_permissions requested when the feature is used.",
        "examples": {"match": ["{ \"manifest_version\": 3,\n  \"permissions\": [\"storage\", \"cookies\", \"debugger\"] }"], "no_match": ["{ \"manifest_version\": 3,\n  \"permissions\": [\"storage\", \"activeTab\"] }"]},
    },
    {
        "id": "ext-weak-csp", "check_id": "EXT-CSP-001", "title": "Extension CSP allows eval or remote scripts", "files": ["config", "js"], "path_includes": MANIFEST,
        "pattern": r"(?i)content_security_policy['\"]?\s*:\s*[^\n]*('unsafe-eval'|'wasm-eval'|script-src[^;\"]*https?:|script-src[^;\"]*\*|'unsafe-inline')",
        "confidence": "HIGH",
        "examples": {"match": ["\"content_security_policy\": { \"extension_pages\": \"script-src 'self' 'unsafe-eval'; object-src 'self'\" }"],
                     "no_match": ["\"content_security_policy\": { \"extension_pages\": \"script-src 'self'; object-src 'self'\" }"]},
    },
    {
        "id": "ext-remote-code", "check_id": "EXT-REMOTE-001", "title": "Remotely hosted or dynamically evaluated code in the extension", "files": ["js", "web"],
        "pattern": r"\beval\(|new\s+Function\(|set(Timeout|Interval)\(\s*['\"`]|importScripts\(\s*['\"`]https?://|<script[^>]+src=['\"]https?://|chrome\.(tabs\.executeScript|scripting\.executeScript)\(\s*[^)]*\bcode\s*:|\.then\(\s*\(?\s*\w+\s*\)?\s*=>\s*eval\(",
        "file_requires": EXT_CTX, "confidence": "HIGH", "note": "Stores reject remote code, and it lets whoever controls the server run code with the extension's permissions.",
        "examples": {"match": ["fetch(CONFIG_URL).then(r => r.text()).then(code => eval(code)); // chrome.runtime", "chrome.tabs.executeScript(tabId, { code: userScript });"],
                     "no_match": ["chrome.scripting.executeScript({ target: { tabId }, files: ['content.js'] });"]},
    },
    {
        "id": "ext-externally-connectable-broad", "check_id": "EXT-MSG-001", "title": "externally_connectable allows broad origins or all extensions", "files": ["config", "js"], "path_includes": MANIFEST,
        "pattern": r"\"externally_connectable\"\s*:\s*\{[^}]*(\"\*\"|<all_urls>|\*://\*|https?://\*/|\*\.[a-z]+/\*\")", "multiline": True, "confidence": "HIGH",
        "examples": {"match": ["\"externally_connectable\": { \"matches\": [\"*://*/*\"] }"], "no_match": ["\"externally_connectable\": { \"matches\": [\"https://app.acme.com/*\"] }"]},
    },
    {
        "id": "ext-external-message-no-sender-check", "check_id": "EXT-MSG-001", "title": "External/page message handler without sender validation", "files": ["js"],
        "pattern": r"(chrome|browser)\.runtime\.onMessageExternal\.addListener\(|(chrome|browser)\.runtime\.onConnectExternal\.addListener\(|window\.addEventListener\(\s*['\"]message['\"]",
        "file_requires": EXT_CTX,
        "not_near": {"pattern": r"sender\.(id|url|origin)|event\.origin|e\.origin|msg\.origin|\.source\s*!==?\s*window|ALLOWED_(ORIGINS|IDS)", "lines": 6},
        "confidence": "MEDIUM",
        "examples": {"match": ["chrome.runtime.onMessageExternal.addListener((msg, sender, reply) => {\n  chrome.cookies.getAll({}, reply);\n});"],
                     "no_match": ["chrome.runtime.onMessageExternal.addListener((msg, sender, reply) => {\n  if (sender.origin !== 'https://app.acme.com') return;\n  reply(status());\n});"]},
    },
    {
        "id": "ext-content-script-innerhtml", "check_id": "EXT-CONTENT-001", "title": "Content script/popup inserts page or message data as HTML", "files": ["js"],
        "pattern": r"(innerHTML|outerHTML)\s*\+?=\s*[^;\n]*(msg|message|data|response|request|document\.|selection|getSelection|title|text|payload)|insertAdjacentHTML\([^,]+,\s*[^)]*(msg|message|data|response|payload)|document\.write\(",
        "file_requires": EXT_CTX, "not_near": {"pattern": r"DOMPurify|sanitize|escapeHtml|textContent", "lines": 2}, "confidence": "MEDIUM",
        "note": "XSS in an extension page runs with the extension's permissions.",
        "examples": {"match": ["chrome.runtime.onMessage.addListener((msg) => { panel.innerHTML = msg.html; });"], "no_match": ["chrome.runtime.onMessage.addListener((msg) => { panel.textContent = msg.text; });"]},
    },
    {
        "id": "ext-war-broad", "check_id": "EXT-WAR-001", "title": "Web-accessible resources exposed to all sites", "files": ["config", "js"], "path_includes": MANIFEST,
        "pattern": r"\"web_accessible_resources\"\s*:\s*\[[^\]]*(\"\*\*?(/\*)?\"|\"[^\"]*\*\.(js|html)\"|<all_urls>|\"\*://\*/\*\")", "multiline": True, "confidence": "LOW",
        "examples": {"match": ["\"web_accessible_resources\": [{ \"resources\": [\"*\"], \"matches\": [\"<all_urls>\"] }]"],
                     "no_match": ["\"web_accessible_resources\": [{ \"resources\": [\"icon.png\"], \"matches\": [\"https://app.acme.com/*\"] }]"]},
    },
    {
        "id": "ext-token-in-sync-storage", "check_id": "EXT-STORAGE-001", "title": "Token or secret stored in storage.sync or localStorage", "files": ["js"],
        "pattern": r"(?i)(chrome|browser)\.storage\.sync\.set\(\s*\{[^}]*(token|secret|password|api_?key|session|jwt|refresh)|localStorage\.setItem\(\s*['\"`][^'\"`]*(token|secret|api_?key|jwt)",
        "file_requires": EXT_CTX, "confidence": "MEDIUM",
        "examples": {"match": ["chrome.storage.sync.set({ accessToken: t });"], "no_match": ["chrome.storage.session.set({ accessToken: t });"]},
    },
    {
        "id": "ext-client-secret", "check_id": "EXT-STORAGE-001", "title": "OAuth client secret or API secret shipped in the extension", "files": ["js", "config"],
        "pattern": r"(?i)\b(client_?secret|api_?secret|secret_?key)\b\s*[:=]\s*['\"](?!{{PLACEHOLDER}})[A-Za-z0-9_\-]{12,}['\"]",
        "file_requires": EXT_CTX, "redact": True, "confidence": "HIGH",
        "examples": {"match": ["const CLIENT_SECRET = 'q8Zr3LmN0vXw2KpT'; // chrome.identity"], "no_match": ["const CLIENT_ID = '1234.apps.googleusercontent.com'; // chrome.identity"]},
    },
    {
        "id": "ext-http-endpoint", "check_id": "EXT-NET-001", "title": "Extension calls a backend over plain HTTP", "files": ["js", "config"],
        "pattern": r"['\"`]http://(?!localhost|127\.0\.0\.1|\*)[\w.-]+", "file_requires": EXT_CTX, "confidence": "MEDIUM",
        "examples": {"match": ["fetch('http://api.acme.com/v1/track', { method: 'POST' }); // chrome.runtime"], "no_match": ["fetch('https://api.acme.com/v1/track', { method: 'POST' }); // chrome.runtime"]},
    },
    {
        "id": "ext-custom-update-url", "check_id": "EXT-UPDATE-001", "title": "Custom update_url (check it's HTTPS and controlled)", "files": ["config", "js"], "path_includes": MANIFEST,
        "pattern": r"\"update_url\"\s*:\s*\"(http://|https://(?!clients2\.google\.com|edge\.microsoft\.com))", "confidence": "MEDIUM",
        "examples": {"match": ["\"update_url\": \"http://updates.acme.com/ext.xml\""], "no_match": ["\"update_url\": \"https://clients2.google.com/service/update2/crx\""]},
    },
]

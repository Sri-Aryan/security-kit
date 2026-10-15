#!/usr/bin/env python3
"""
SecurityKit webhook finder (static, read-only, standard library only).

Language- and provider-agnostic. Finds:
  * inbound receivers: routes whose path looks like a webhook, or code that verifies webhook signatures
  * outbound senders: code that sends HTTP requests to a user-configured URL (webhook_url, callback_url, ...)
and, for each, which security *concepts* are visible nearby (signature verification, raw body, constant-time
compare, timestamp tolerance, idempotency, SSRF protection, redirects, timeouts, signing).

Verification helpers referenced from a receiver (e.g. verifyStripeSignature) are followed into the files
that define them. Prints JSON: { receivers, senders, candidates, warnings }. Candidates are leads; the agent
confirms or rejects each by reading the code.
"""

import argparse
import bisect
import json
import os
import re
import sys

VERSION = "0.1.0"
SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "target", "out", ".next", ".nuxt", "__pycache__",
    ".venv", "venv", "env", ".tox", ".securitykit", ".claude", ".codex", "coverage", ".idea", ".vscode",
    "bin", "obj", ".gradle",
}
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "testdata", "e2e"}
TEST_FILE_RE = re.compile(r"(\.(test|spec)\.[cm]?[jt]sx?$)|(^test_.*\.py$)|(_test\.(py|go)$)|(Tests?\.(java|kt|cs)$)|(_spec\.rb$)")
CODE_EXT = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx", ".py", ".rb", ".go", ".java", ".kt",
            ".cs", ".php", ".ex", ".exs", ".scala", ".rs"}
MAX_BYTES = 1_500_000
REGION_LINES = 150

# --------------------------------------------------------------------------- concept signals

RX = lambda s: re.compile(s, re.I)

WEBHOOK_PATH = re.compile(
    r"""['"`](/(?:[^'"`\s]*?/)?(?:web-?hooks?|hooks?|callbacks?|ipn|incoming)\b[^'"`\s]*|/[^'"`\s]*webhook[^'"`\s]*)['"`]""",
    re.I,
)
NOT_WEBHOOK_PATH = RX(r"oauth|/auth/|login|sso|saml|openid|signin|sign-in")
ROUTE_CONTEXT = RX(
    r"\b(get|post|put|route|all|use|Post|Mapping|HandleFunc|Handle|path|re_path|url|add_url_rule|match|"
    r"MapPost|MapGet|POST|Any|HandlerFunc)\s*\(|@\w*(route|post|Post|Mapping)\b|\bpost\s+['\"]"
)
ANY_ROUTE = RX(
    r"\.(get|post|put|patch|delete|all|route)\s*\(\s*['\"`]/|@\w*\.?(route|post|get|put|patch|delete)\s*\(|"
    r"@(Get|Post|Put|Patch|Delete|Request)Mapping\b|HandleFunc\s*\(|\b(path|re_path)\s*\(\s*['\"]|"
    r"\b(get|post|put|patch|delete)\s+['\"]/|Map(Get|Post|Put|Delete)\s*\("
)

SIG = {
    "signature_header": RX(
        r"x-[\w-]*signature[\w-]*|[\w-]+-signature\b|x-hub-signature(-256)?|stripe-signature|svix-signature|"
        r"webhook-signature|x-slack-signature|x-twilio-signature|x-shopify-hmac-sha256|x-gitlab-token|"
        r"x-line-signature|paypal-transmission-sig|x-square-hmacsha256-signature|x-hook-signature"
    ),
    "hmac": re.compile(
        r"createHmac|hmac\.new|hmac\.HMAC|\bHMAC\s*\(|Mac\.getInstance|hmac\.New\s*\(|OpenSSL::HMAC|hash_hmac|"
        r"HMACSHA256|HmacSHA256|crypto\.subtle\.(sign|verify)|createVerify|ed25519|nacl\.sign|Signature\.getInstance"
    ),
    "sdk_verify": re.compile(
        r"constructEvent|construct_event|webhooks?\.verify|verifyWebhook|verify_webhook|validateRequest|"
        r"validate_request|RequestValidator|verifyRequestSignature|WebhookSignature|validateWebhook|"
        r"isValidSignature|verifyHeader|verify_header|Webhook\s*\([^)]*\)\s*\.verify|wh\.verify|"
        r"Svix|svix\.Webhook|WebhookVerifier|verifyNotificationSignature|verify_notification"
    ),
    "const_time": re.compile(
        r"timingSafeEqual|compare_digest|MessageDigest\.isEqual|ConstantTimeCompare|secure_compare|hash_equals|"
        r"FixedTimeEquals|constant_time_compare|safe_str_cmp|constantTimeEquals|ActiveSupport::SecurityUtils|"
        r"crypto\.subtle\.verify|hmac\.Equal"
    ),
    "raw_body": re.compile(
        r"express\.raw|bodyParser\.raw|\braw\s*\(\s*\{|rawBody|raw_body|get_data\s*\(|request\.body\b|"
        r"await\s+request\.body\s*\(|ReadAll\s*\(\s*\w+\.Body|getInputStream|req\.rawBody|Buffer\.concat|"
        r"@RequestBody\s+(String|byte\[\])|request\.raw_post|php://input|EnableBuffering|\.arrayBuffer\s*\(|"
        r"await\s+req\.text\s*\(|request\.get_data|verify\s*:\s*\(\s*req\s*,\s*res\s*,\s*buf"
    ),
    "reserialize": re.compile(r"(createHmac|hmac|HMAC|digest|update)[^\n]{0,80}(JSON\.stringify\s*\(\s*req\.body|json\.dumps\s*\(\s*(request\.json|payload|data|body)|JSON\.generate|json\.Marshal\s*\(\s*(payload|event|body))"),
    "timestamp": RX(r"timestamp|tolerance|x-[\w-]*-timestamp|request-timestamp|svix-timestamp|\bt=|max_?age|replay|\b300\b|5\s*\*\s*60"),
    "tolerance_off": RX(r"tolerance\s*[:=]\s*(0|None|null|-1|Infinity|math\.MaxInt|Number\.MAX)"),
    "idempotency": RX(
        r"idempot|event_?id|eventId|event\.id|delivery_?id|x-github-delivery|webhook-id|svix-id|"
        r"already[_ ]?processed|processed_?events|dedup|ON\s+CONFLICT|upsert|SETNX|setIfAbsent|"
        r"get_or_create|findOrCreate|unique_?constraint|IntegrityError|duplicate"
    ),
    "queue": RX(r"queue|enqueue|celery|sidekiq|bull|\bsqs\b|pubsub|background|apply_async|delay\s*\(|go\s+func|Task\.Run|perform_later|jobs?\.(add|create)"),
    "fail_open": RX(
        r"if\s*\(?\s*(process\.env\.|os\.environ|settings\.|config\.|ENV\[)?[\w.\[\]'\"]*secret[\w\]'\"]*\s*\)?\s*[:{]|"
        r"(skip|disable|bypass)[_ ]?(signature|verification|verify)|verify(_signature|Signature)?\s*[:=]\s*(false|False)"
    ),
    "csrf_exempt": RX(r"csrf_exempt|skip_before_action\s*:verify_authenticity_token|IgnoreAntiforgeryToken|csrf\(\)\.ignoring|ignoringRequestMatchers|csrf\.exempt|@csrf\.exempt"),
}
HARDCODED_SECRET = re.compile(
    r"\bwhsec_[A-Za-z0-9+/=]{10,}|"
    r"(?i:(webhook|signing|hook|endpoint)[_-]?secret)\s*[:=]\s*['\"](?!\s*$)(?!.*(env|ENV|changeme|example|your))[^'\"\s]{8,}['\"]"
)
UNSAFE_COMPARE = re.compile(r"(?i)(signature|\bsig\b|digest|hmac|expected|computed)[^\n]{0,60}(===|!==|==|!=|\.equals\(|\.Equals\()|(===|!==|==|!=|\.equals\(|\.Equals\()[^\n]{0,60}(signature|\bsig\b|digest|hmac)")

HELPER_NAME = re.compile(
    r"\b(\w*(?:verify|validate|check|authenticate|assert)\w*(?:signature|sig|webhook|hmac|request|event|payload)\w*|"
    r"\w*(?:signature|webhook|hmac)\w*(?:verify|valid|check|guard|middleware)\w*)\b",
    re.I,
)

OUT_URL_FIELD = RX(
    r"\b(webhook_?url|callback_?url|hook_?url|notify_?url|notification_?url|endpoint_?url|target_?url|"
    r"destination_?url|delivery_?url|subscriber_?url|postback_?url|webhook_?endpoint|webhookUri|callbackUri)\b"
)
HTTP_CLIENT = re.compile(
    r"\bfetch\s*\(|axios(\.\w+)?\s*\(|\bgot(\.\w+)?\s*\(|\brequest\s*\(|requests\.(post|get|put|request)\s*\(|"
    r"httpx\.|aiohttp|urllib\.request|urlopen\s*\(|http\.(Post|Get|NewRequest)|\.Do\s*\(\s*req|HttpClient|"
    r"RestTemplate|WebClient|Net::HTTP|Faraday|HTTParty|curl_exec|Guzzle|HttpURLConnection|OkHttpClient|"
    r"https?\.request\s*\(|undici|ky\s*\("
)
OUT = {
    "ssrf_guard": RX(
        r"is_?private|isPrivate|is_loopback|isLoopback|is_link_local|isLinkLocal|ipaddress\.|ip_address\s*\(|"
        r"net\.ParseIP|IsPrivate\s*\(|IsLoopback|InetAddress|private[_ ]?ip|ssrf|169\.254\.169\.254|"
        r"blocklist|denylist|allowlist|dns\.lookup|getaddrinfo|LookupIP|resolve4|request-filtering-agent|"
        r"ssrf-req-filter|safe_?url|validate_?url|is_?public_?url|isPublicUrl|private_?network|ipaddr"
    ),
    "no_redirect": RX(
        r"maxRedirects\s*:\s*0|allow_redirects\s*=\s*False|redirect\s*:\s*['\"](manual|error)|follow_redirects\s*=\s*False|"
        r"CheckRedirect|followRedirects\s*\(\s*false|setInstanceFollowRedirects\s*\(\s*false|Redirect\.NEVER|"
        r"followRedirects?\s*:\s*false|AllowAutoRedirect\s*=\s*false|max_redirects\s*=\s*0"
    ),
    "timeout": RX(r"timeout"),
    "signing": SIG["hmac"],
    "https_only": RX(r"(scheme|protocol)[^\n]{0,40}https|startswith\(\s*['\"]https://|startsWith\(\s*['\"]https://|https:\\/\\/\^|\^https"),
    "tls_off": RX(r"rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|ssl_verify\s*=\s*False|VERIFY_NONE"),
    "response_exposed": RX(r"(response|res|resp|r)\.(text|body|data|content)\b[^\n]{0,80}(json|send|render|return|save|store|log_?entry|last_?response)"),
}


class LineIndex:
    def __init__(self, text):
        self.starts = [0] + [m.end() for m in re.finditer(r"\n", text)]

    def line(self, offset):
        return bisect.bisect_right(self.starts, offset)


def walk(root, include_tests):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")
                             and (include_tests or d not in TEST_DIRS))
        for f in sorted(filenames):
            if (not include_tests and TEST_FILE_RE.search(f)) or os.path.splitext(f)[1].lower() not in CODE_EXT:
                continue
            full = os.path.join(dirpath, f)
            try:
                if os.path.getsize(full) <= MAX_BYTES:
                    with open(full, encoding="utf-8", errors="replace") as fh:
                        yield full, fh.read()
            except OSError:
                continue


def hits(rx, lines, start, end):
    """[(line_no, text)] for lines[start:end] (1-based line numbers) matching rx."""
    return [(i + 1, lines[i].strip()[:160]) for i in range(max(0, start), min(len(lines), end)) if rx.search(lines[i])]


def scan(root, include_tests=False):
    root = os.path.abspath(root)
    files = {}
    for path, text in walk(root, include_tests):
        files[os.path.relpath(path, root).replace(os.sep, "/")] = text
    lines = {f: t.splitlines() for f, t in files.items()}

    # Where helpers are defined: name -> [(file, line)]
    def find_definitions(name):
        rx = re.compile(
            r"(function\s+%s\b|def\s+%s\b|func\s+(\([^)]*\)\s*)?%s\b|\b(const|let|var)\s+%s\s*=|"
            r"\b%s\s*[:=]\s*(async\s*)?(function|\()|(public|private|protected|static|internal)[\w<>\[\]\s]*\s%s\s*\()"
            % ((re.escape(name),) * 6)
        )
        out = []
        for f, ls in lines.items():
            for i, l in enumerate(ls):
                if rx.search(l):
                    out.append((f, i + 1))
        return out[:3]

    project_signal = lambda rx: any(rx.search(t) for t in files.values())

    receivers, senders, candidates, warnings = [], [], [], []

    def cand(check_id, title, file, line, confidence, note):
        snippet = lines[file][line - 1].strip()[:200] if file and line and line <= len(lines[file]) else ""
        candidates.append({"check_id": check_id, "title": title, "file": file, "line": line,
                           "snippet": snippet, "confidence": confidence, "note": note})

    # ---------------------------------------------------------------- inbound receivers
    found = []  # (file, line, path)
    for f, text in files.items():
        ls = lines[f]
        idx = LineIndex(text)
        for m in WEBHOOK_PATH.finditer(text):
            line = idx.line(m.start())
            path = m.group(1)
            if NOT_WEBHOOK_PATH.search(path) or not ROUTE_CONTEXT.search(ls[line - 1]):
                continue
            found.append((f, line, path))

    covered = set()  # files reached as a receiver or a helper

    def process(f, line, path):
        ls = lines[f]
        route_lines = sorted({i + 1 for i, l in enumerate(ls) if ANY_ROUTE.search(l)})
        covered.add(f)
        nxt = next((r for r in route_lines if r > line), None)
        end = min(nxt - 1 if nxt else len(ls), line - 1 + REGION_LINES)
        region = (line - 1, end)
        region_text = "\n".join(ls[region[0]:region[1]])
        helpers = []
        for name in sorted(set(HELPER_NAME.findall(region_text))):
            for hf, hl in find_definitions(name):
                if hf == f and region[0] < hl <= region[1]:
                    continue
                helpers.append({"name": name, "file": hf, "line": hl})
        spans = [(f, region[0], region[1])] + [(h["file"], h["line"] - 1, h["line"] - 1 + 80) for h in helpers]

        def seen(key, rx=None):
            rx = rx or SIG[key]
            out = []
            for sf, s, e in spans:
                out += [{"file": sf, "line": ln, "text": t} for ln, t in hits(rx, lines[sf], s, e)]
            return out

        sig = {k: seen(k) for k in SIG}
        file_level = {k: [{"file": f, "line": ln, "text": t} for ln, t in hits(SIG[k], ls, 0, len(ls))]
                      for k in ("raw_body", "hmac", "sdk_verify", "const_time")}
        unsafe = [h for h in seen("unsafe", UNSAFE_COMPARE) if not SIG["const_time"].search(h["text"])]
        receivers.append({
            "path": path, "file": f, "line": line,
            "helpers": helpers,
            "signals": {k: v[:5] for k, v in sig.items() if v},
        })

        verified = bool(sig["hmac"] or sig["sdk_verify"])
        name = path or f"{f}:{line}"
        if not verified:
            weak = file_level["hmac"] or file_level["sdk_verify"]
            cand("WH-SIG-001", f"No signature verification found for receiver {name}", f, line,
                 "MEDIUM" if weak else "HIGH",
                 "verification code exists elsewhere in this file; confirm it runs for this route" if weak
                 else "no HMAC/signature/SDK verification in the handler or the helpers it calls")
        if sig["hmac"] and not sig["sdk_verify"]:
            if unsafe:
                u = unsafe[0]
                cand("WH-SIG-003", "Signature compared with a non-constant-time operator", u["file"], u["line"], "HIGH", "")
            elif not sig["const_time"]:
                cand("WH-SIG-003", f"No constant-time comparison found for receiver {name}", f, line, "MEDIUM", "")
            if not (sig["raw_body"] or file_level["raw_body"] or project_signal(SIG["raw_body"])):
                cand("WH-SIG-002", f"Signature may not be computed over the raw body ({name})", f, line, "MEDIUM",
                     "no raw-body access found; confirm the HMAC input is the exact received bytes")
            if not sig["timestamp"]:
                cand("WH-REPLAY-001", f"No timestamp tolerance check found ({name})", f, line, "MEDIUM", "")
        for r in sig["reserialize"]:
            cand("WH-SIG-002", "HMAC computed over re-serialized JSON", r["file"], r["line"], "HIGH",
                 "re-serialized JSON differs from the bytes that were signed")
        for r in sig["tolerance_off"]:
            cand("WH-REPLAY-001", "Timestamp tolerance disabled", r["file"], r["line"], "HIGH", "")
        for r in sig["fail_open"]:
            cand("WH-SIG-004", "Verification may be skipped (fail-open)", r["file"], r["line"], "MEDIUM",
                 "confirm a missing secret / flag cannot disable verification")
        if verified and not sig["idempotency"]:
            cand("WH-IDEM-001", f"No duplicate-delivery handling found ({name})", f, line, "LOW",
                 "providers retry; confirm side effects are applied once per event ID")
        if not sig["queue"]:
            cand("WH-PROC-003", f"Receiver appears to process synchronously ({name})", f, line, "LOW", "")

    for f, line, path in found:
        process(f, line, path)
    # Verification code no detected receiver reaches (e.g. a route registered in a way we do not parse).
    helper_files = {h["file"] for r in receivers for h in r["helpers"]}
    for f, text in files.items():
        if f in covered or f in helper_files:
            continue
        if SIG["sdk_verify"].search(text) or (SIG["signature_header"].search(text) and SIG["hmac"].search(text)):
            m = SIG["sdk_verify"].search(text) or SIG["signature_header"].search(text)
            process(f, LineIndex(text).line(m.start()), None)

    # ---------------------------------------------------------------- global inbound signals
    for f, text in files.items():
        idx = LineIndex(text)
        for m in HARDCODED_SECRET.finditer(text):
            cand("WH-SIG-005", "Hardcoded webhook secret", f, idx.line(m.start()), "HIGH", "")
        for m in SIG["csrf_exempt"].finditer(text):
            cand("WH-PROC-005", "CSRF exemption: confirm it is scoped to the webhook route only", f, idx.line(m.start()), "LOW", "")

    # ---------------------------------------------------------------- outbound senders
    ssrf_anywhere = [f for f, t in files.items() if OUT["ssrf_guard"].search(t)]
    for f, text in files.items():
        if not OUT_URL_FIELD.search(text) or not HTTP_CLIENT.search(text):
            continue
        ls = lines[f]
        client_lines = [i + 1 for i, l in enumerate(ls) if HTTP_CLIENT.search(l)]
        field_lines = [i + 1 for i, l in enumerate(ls) if OUT_URL_FIELD.search(l)]
        line = next((c for c in client_lines if c >= field_lines[0]), client_lines[0])
        sig = {k: hits(rx, ls, 0, len(ls)) for k, rx in OUT.items()}
        senders.append({"file": f, "line": line, "url_fields": sorted({m.group(0) for m in OUT_URL_FIELD.finditer(text)}),
                        "signals": {k: [{"line": ln, "text": t} for ln, t in v[:5]] for k, v in sig.items() if v}})
        if not sig["ssrf_guard"]:
            if ssrf_anywhere:
                cand("WH-OUT-001", "Outbound webhook delivery: SSRF guard not visible here", f, line, "MEDIUM",
                     f"guard-like code exists in {', '.join(ssrf_anywhere[:3])}; confirm it runs for this request, at delivery time")
            else:
                cand("WH-OUT-001", "Outbound webhook delivery to a user-supplied URL without SSRF protection", f, line, "HIGH",
                     "no private-IP / DNS / allow-list checks found anywhere in the project")
        if not sig["no_redirect"]:
            cand("WH-OUT-002", "Redirects may be followed for outbound deliveries", f, line, "MEDIUM", "")
        if not sig["signing"]:
            cand("WH-OUT-003", "Outbound deliveries do not appear to be signed", f, line, "MEDIUM", "")
        if not sig["timeout"]:
            cand("WH-OUT-005", "No timeout on outbound deliveries", f, line, "MEDIUM", "")
        for ln, _ in sig["tls_off"]:
            cand("WH-OUT-009", "TLS verification disabled for outbound deliveries", f, ln, "HIGH", "")
        for ln, _ in sig["response_exposed"][:2]:
            cand("WH-OUT-006", "Subscriber response may be stored or shown to users", f, ln, "LOW",
                 "confirm response bodies are not displayed (blind SSRF -> full SSRF)")

    if not receivers and not senders:
        warnings.append("no webhook receivers or senders found")
    return {"tool": "securitykit-find-webhooks", "version": VERSION, "root": ".",
            "receivers": receivers, "senders": senders, "candidates": candidates, "warnings": warnings}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Find webhook receivers/senders and missing controls (SecurityKit).")
    ap.add_argument("--root", default=".")
    ap.add_argument("--out")
    ap.add_argument("--include-tests", action="store_true")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)
    if not os.path.isdir(args.root):
        print(f"error: not a directory: {args.root}", file=sys.stderr)
        return 2
    result = scan(args.root, args.include_tests)
    text = json.dumps(result, indent=2)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"{len(result['receivers'])} receivers, {len(result['senders'])} senders, "
              f"{len(result['candidates'])} candidates -> {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

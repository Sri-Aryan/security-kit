#!/usr/bin/env python3
"""
SecurityKit audit helper (read-only on the project, standard library only).

  python3 audit.py plan  --root .     # which installed skills apply to this project, and why
  python3 audit.py merge --root .     # combine .securitykit/*report.json into one deduplicated report + score

plan   looks for technology signals (manifests, file names, imports) and lists the relevant skills with the evidence.
merge  reads every SecurityKit skill report, merges findings that point at the same place and weakness (same file,
       nearby lines, shared CWE or check ID), keeps the highest severity, and writes
       .securitykit/audit-report.json and security-report-audit.md.
"""

import argparse
import datetime
import glob
import json
import os
import re
import sys

VERSION = "0.1.0"
SEVERITIES = ["Critical", "High", "Medium", "Low"]
WEIGHT = {"Critical": 25, "High": 10, "Medium": 4, "Low": 1}
LINE_SLACK = 3

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "target", "out", ".next", ".nuxt", "__pycache__", ".venv",
    "venv", "env", ".tox", ".mypy_cache", ".pytest_cache", ".securitykit", ".claude", ".codex", "coverage",
    ".idea", ".vscode", "bin", "obj", "Pods", ".gradle", ".terraform", "site-packages",
}
CODE_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".py", ".go", ".java", ".kt", ".rb", ".php", ".cs",
            ".rs", ".c", ".cc", ".cpp", ".h", ".swift", ".vue", ".svelte", ".html", ".ejs", ".hbs", ".jinja", ".erb",
            ".json", ".yml", ".yaml", ".toml", ".xml", ".gradle", ".kts", ".tf", ".graphql", ".gql", ".prisma", ".sql"}

# (skill, path regex, content regex, reason). A skill is relevant when either regex matches somewhere.
SIGNALS = [
    ("sk-api", None, r"\bexpress\b|fastify|@nestjs|koa|hapi|from fastapi|flask|django|spring-boot|@RestController|gin-gonic|labstack/echo|go-chi|gorilla/mux|net/http|rails|laravel|aspnetcore|MapGet\(", "HTTP API framework"),
    ("sk-rest", None, r"\bexpress\b|fastify|@nestjs|from fastapi|flask|django|spring-boot|gin-gonic|labstack/echo|go-chi|rails|laravel|aspnetcore", "REST endpoints"),
    ("sk-graphql", r"\.(graphql|gql)$", r"graphql|apollo-server|@apollo/server|graphene|strawberry|gqlgen|hotchocolate", "GraphQL"),
    ("sk-openapi", r"(?i)(openapi|swagger)[^/]*\.(ya?ml|json)$", r"swagger-ui|springdoc|drf-spectacular|@nestjs/swagger|swaggo", "OpenAPI spec"),
    ("sk-webhooks", None, r"(?i)webhook", "webhooks"),
    ("sk-auth", None, r"(?i)passport|next-auth|authjs|lucia|devise|django\.contrib\.auth|flask[-_]login|spring-security|express-session|login|signin|sign_in", "login / sessions"),
    ("sk-password", None, r"(?i)bcrypt|argon2|scrypt|pbkdf2|password_hash|PasswordEncoder|passlib|reset[-_]?password", "password storage / reset"),
    ("sk-tokens", None, r"(?i)jsonwebtoken|\bjose\b|pyjwt|\bjwt\b|api[-_]?key|refresh[-_]?token", "tokens / JWT / API keys"),
    ("sk-oauth2", None, r"(?i)oauth|openid|oidc|authorization_code|passport-google|next-auth/providers|authlib|spring-security-oauth2|keycloak|auth0|okta|cognito", "OAuth 2.0 / OIDC"),
    ("sk-secrets", None, None, "always: hardcoded and leaked secrets"),
    ("sk-database", r"\.(sql|prisma)$|(^|/)migrations?/", r"(?i)\b(pg|mysql2?|sqlite3?|mongoose|mongodb|prisma|sequelize|typeorm|knex|drizzle|sqlalchemy|psycopg|pymongo|gorm|database/sql|hibernate|jdbc|activerecord|eloquent|entityframework|redis)\b", "database access"),
    ("sk-inject", None, None, "always: injection in any interpreter"),
    ("sk-xss", r"\.(html|ejs|hbs|jinja|j2|erb|twig|cshtml|jsp|vue|svelte|jsx|tsx)$", r"innerHTML|dangerouslySetInnerHTML|render_template|res\.render", "HTML rendering"),
    ("sk-upload", None, r"(?i)multer|busboy|formidable|multipart|UploadFile|request\.files|MultipartFile|IFormFile|presigned|getSignedUrl|generate_presigned|upload", "file uploads"),
    ("sk-deserialize", None, r"\bpickle\b|yaml\.(load|unsafe_load)|ObjectInputStream|BinaryFormatter|unserialize\(|Marshal\.load|node-serialize|TypeNameHandling|enableDefaultTyping|_\.merge\(|torch\.load|joblib\.load", "deserialization / deep merge"),
    ("sk-ssrf", None, r"\baxios\b|node-fetch|\bfetch\(|requests\.(get|post)|httpx|urllib|http\.Get|RestTemplate|WebClient|HttpClient|Net::HTTP|Guzzle|puppeteer|playwright", "server-side HTTP requests"),
    ("sk-redirect", None, r"(?i)\bredirect\(|sendRedirect|redirect_to|returnUrl|return_to|\bnext=", "redirects"),
    ("sk-ratelimit", None, r"\bexpress\b|fastify|@nestjs|from fastapi|flask|django|spring-boot|gin-gonic|rails|laravel|aspnetcore", "public endpoints need limits"),
    ("sk-business", None, r"(?i)\b(order|cart|checkout|coupon|discount|balance|credit|invoice|subscription|quota|plan)\b", "business workflows"),
    ("sk-race", None, r"(?i)\b(balance|stock|inventory|quantity|coupon|redeem|withdraw|transfer|seat|booking)\b", "shared counters / single-use resources"),
    ("sk-payments", None, r"(?i)stripe|paypal|braintree|adyen|square|razorpay|mollie|paddle|lemonsqueezy|checkout\.session", "payments"),
    ("sk-email", None, r"(?i)nodemailer|smtplib|sendgrid|mailgun|postmark|resend|@aws-sdk/client-ses|ses\.send|twilio|ActionMailer|JavaMailSender|MailKit|send_mail", "email / SMS"),
    ("sk-ai", None, r"(?i)\bopenai\b|@anthropic-ai|\banthropic\b|langchain|llamaindex|@ai-sdk|\bollama\b|google-generativeai|@google/genai|bedrock-runtime|transformers|huggingface", "LLM features"),
    ("sk-prompt-injection", None, r"(?i)\bopenai\b|@anthropic-ai|\banthropic\b|langchain|llamaindex|@ai-sdk|\bollama\b|google-generativeai|@google/genai|bedrock-runtime", "LLM prompts"),
    ("sk-agents", r"(?i)(^|/)(\.mcp\.json|mcp\.json|claude_desktop_config\.json)$", r"(?i)modelcontextprotocol|FastMCP|McpServer|langgraph|AgentExecutor|crewai|autogen|@openai/agents|tool_calls|bind_tools|server\.tool\(", "agents / tools / MCP"),
    ("sk-rag", None, r"(?i)pinecone|weaviate|qdrant|chroma|pgvector|milvus|faiss|lancedb|embeddings?\.create|vector_?store|VectorStore|similarity_search", "retrieval / vector store"),
    ("sk-docker", r"(?i)(^|/)(Dockerfile[^/]*|Containerfile|[^/]*compose[^/]*\.ya?ml|.*\.dockerfile)$|(^|/)(k8s|kubernetes|helm|charts)/", None, "containers / Kubernetes"),
    ("sk-cicd", r"(^|/)(\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|\.circleci/config\.ya?ml|azure-pipelines\.ya?ml|Jenkinsfile|bitbucket-pipelines\.ya?ml)$", None, "CI/CD pipelines"),
    ("sk-tests", None, None, "always: security test gaps"),
    ("sk-fuzz", r"\.(c|cc|cpp|rs|go)$", r"(?i)\b(parse|decode|unmarshal|deserialize)\w*\s*\(", "parsers / native code"),
    ("sk-design", None, None, "always: threat model (interactive, run when time allows)"),
    ("sk-validation", None, None, "always: input validation at entry points"),
    ("sk-authz", None, r"(?i)\b(role|roles|permission|is_?admin|tenant|org_?id|policy|authorize)\b", "access control"),
    ("sk-crypto", None, r"(?i)createCipheriv|crypto\.subtle|Cipher\.getInstance|from\s+cryptography|Crypto\.Cipher|createHmac|hashlib|crypto/aes|javax\.crypto|rejectUnauthorized|verify\s*=\s*False", "cryptography / TLS"),
    ("sk-logging", None, None, "always: security logging and monitoring"),
    ("sk-config", None, None, "always: production configuration"),
    ("sk-deps", r"(?i)(^|/)(package\.json|requirements[^/]*\.txt|pyproject\.toml|go\.mod|Gemfile|composer\.json|Cargo\.toml|pom\.xml|build\.gradle(\.kts)?|pubspec\.yaml|[^/]*\.csproj)$", None, "third-party dependencies"),
    ("sk-privacy", None, r"(?i)\b(email|phone|address|date_?of_?birth|ssn|analytics\.|mixpanel|segment|posthog|gtag)\b", "personal data"),
    ("sk-csrf", None, r"(?i)express-session|cookie-session|req\.session|SessionMiddleware|res\.cookie\(|set_cookie|csrf", "cookie sessions"),
    ("sk-browser", r"\.(html|ejs|hbs|jinja|j2|erb|twig|cshtml|jsp|vue|svelte|jsx|tsx)$", r"(?i)helmet|Content-Security-Policy|localStorage", "browser-facing app"),
    ("sk-dos", None, r"\bexpress\b|fastify|@nestjs|from fastapi|flask|django|spring-boot|gin-gonic|rails|laravel|aspnetcore", "request handling limits"),
    ("sk-cache", None, r"(?i)Cache-Control|cache_page|@Cacheable|revalidate|unstable_cache|redis|memcache|proxy_cache|cloudfront|varnish", "caching"),
    ("sk-cloud", r"(?i)\.(tf|tfvars|bicep)$|(^|/)(serverless\.ya?ml|template\.ya?ml|samconfig\.toml|Pulumi\.ya?ml|cdk\.json)$", r"AWSTemplateFormatVersion", "infrastructure as code"),
    ("sk-websocket", None, r"(?i)\bws\b['\"]|socket\.io|WebSocketServer|websockets|channels\.generic|SignalR|ActionCable|EventSource|text/event-stream|pusher|ably", "real-time channels"),
    ("sk-grpc", r"\.proto$", r"(?i)grpc|tonic::", "gRPC services"),
    ("sk-queue", None, r"(?i)bullmq|\bbull\b|celery|sidekiq|\brq\b|resque|hangfire|amqplib|kafkajs|confluent_kafka|@aws-sdk/client-sqs|sqs\.|pika|ShouldQueue|oban|temporalio", "queues / background jobs"),
    ("sk-saml", None, r"(?i)passport-saml|node-saml|samlify|python3-saml|onelogin|ruby-saml|pysaml2|Saml2|SAMLResponse", "SAML SSO"),
    ("sk-mobile", r"(?i)(^|/)(AndroidManifest\.xml|Info\.plist|pubspec\.yaml|Podfile|app\.json|capacitor\.config\.\w+)$", r"(?i)react-native|expo\b|@capacitor|flutter", "mobile app"),
    ("sk-electron", None, r"(?i)\belectron\b|BrowserWindow|@tauri-apps|tauri\.conf", "desktop app"),
    ("sk-extension", None, r"\"manifest_version\"\s*:\s*[23]|chrome\.runtime|browser\.runtime", "browser extension"),
    ("sk-domain", None, r"(?i)aws_route53_record|cloudflare_(dns_)?record|azurerm_dns_|google_dns_record_set|v=spf1|v=DMARC1", "DNS / email authentication"),
    ("sk-repo", r"(^|/)\.git(ignore|attributes)$|(^|/)\.github/", None, "repository hygiene"),
    ("sk-incident", None, None, "always: incident readiness (interactive)"),
    ("sk-baas", r"(?i)(^|/)(supabase/|firestore\.rules$|storage\.rules$|database\.rules\.json$|firebase\.json$|pb_migrations/|convex/|amplify/data/)", r"(?i)@supabase/|supabase_flutter|from\s+supabase\s+import|firebase/(app|firestore|database|storage)|firebase-admin|\bappwrite\b|pocketbase|from\s+['\"]convex/|aws-amplify", "backend-as-a-service (Supabase, Firebase, ...)"),
    ("sk-nextjs", r"(?i)(^|/)(next\.config\.[cm]?[jt]s|svelte\.config\.js|nuxt\.config\.[jt]s|remix\.config\.js|react-router\.config\.ts|astro\.config\.mjs)$", r"['\"]use server['\"]|from\s+['\"]next/|@sveltejs/kit|@remix-run/|from\s+['\"]#app", "full-stack framework (Next.js, SvelteKit, Nuxt, Remix)"),
    ("sk-authprovider", None, r"(?i)@clerk/|next-auth|@auth/|better-auth|['\"]lucia['\"]|@auth0/|@supabase/(ssr|auth-helpers)|firebase/auth|@kinde-oss/|@workos-inc/|@stackframe/|aws-amplify/auth|@propelauth/|stytch|@descope/", "hosted auth provider / auth library"),
    ("sk-passkeys", None, r"(?i)@simplewebauthn|webauthn|navigator\.credentials\.(create|get)|passkey|fido2|magic.?link|signInWithOtp|sendSignInLinkToEmail|verify_?otp|one.?time.?(code|password)", "passkeys, magic links or one-time codes"),
    ("sk-abuse", None, r"(?i)\b(sign_?up|signup|register|free_?trial|trial_period|credits|referral|captcha|turnstile|quota|free_?tier)\b", "sign-up, trials, credits or referrals"),
    ("sk-paas", r"(?i)(^|/)(vercel\.json|netlify\.toml|_headers|_redirects|wrangler\.(toml|jsonc?)|render\.ya?ml|fly\.toml|railway\.(json|toml)|Procfile|firebase\.json|apphosting\.ya?ml|\.do/app\.ya?ml|amplify\.ya?ml)$", None, "hosting platform config"),
    ("sk-game", r"(?i)(^|/)(ProjectSettings/ProjectVersion\.txt|project\.godot|[^/]*\.uproject|default\.project\.json|[^/]*\.rbxlx?|[^/]*\.luau)$", r"UnityEngine|Unity\.Netcode|\bMirror\b|Photon\.|PlayFab|Nakama|colyseus|\bphaser\b|OnServerEvent|RemoteEvent", "game client or game server"),
    ("sk-ai-code", None, None, "always: shortcuts typical of AI-written code"),
    ("sk-defaults", None, None, "always: insecure defaults and fail-open checks"),
]


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not (d.startswith(".") and d not in (".github", ".gitlab", ".circleci")))
        for f in sorted(filenames):
            yield os.path.relpath(os.path.join(dirpath, f), root).replace(os.sep, "/")


def read(root, rel, limit=400_000):
    try:
        with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def installed_skills(skills_dir):
    return sorted(d for d in os.listdir(skills_dir) if d.startswith("sk-") and os.path.isfile(os.path.join(skills_dir, d, "SKILL.md")))


# --------------------------------------------------------------------------- plan

def plan(root, skills_dir, max_files):
    files = list(walk(root))
    special = [f for f in files if os.path.basename(f) == "Jenkinsfile" or f.endswith(".mcp.json")]
    code = [f for f in files if os.path.splitext(f)[1].lower() in CODE_EXT][:max_files] + special
    texts = {f: read(root, f) for f in code}
    have = set(installed_skills(skills_dir))
    rows = []
    for skill, path_rx, content_rx, reason in SIGNALS:
        evidence = None
        if path_rx is None and content_rx is None:
            evidence = "always"
        if not evidence and path_rx:
            hit = next((f for f in files if re.search(path_rx, f)), None)
            evidence = hit and f"file {hit}"
        if not evidence and content_rx:
            rx = re.compile(content_rx)
            for f, t in texts.items():
                m = rx.search(t)
                if m:
                    evidence = f"{f}:{t.count(chr(10), 0, m.start()) + 1} ({m.group(0)[:40]})"
                    break
        rows.append({"skill": skill, "relevant": bool(evidence), "installed": skill in have,
                     "reason": reason, "evidence": evidence})
    return {"tool": "securitykit-audit-plan", "version": VERSION, "files_considered": len(texts),
            "run": [r for r in rows if r["relevant"] and r["installed"]],
            "not_installed": [r["skill"] for r in rows if r["relevant"] and not r["installed"]],
            "not_relevant": [r["skill"] for r in rows if not r["relevant"]]}


# --------------------------------------------------------------------------- merge

def load_reports(sk_dir, include_review, warnings):
    reports = []
    for path in sorted(glob.glob(os.path.join(sk_dir, "*report.json"))):
        name = os.path.basename(path)
        if name == "audit-report.json" or (name == "review-report.json" and not include_review):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as e:
            warnings.append(f"{name}: unreadable ({e})")
            continue
        tool = data.get("tool") or {}
        if tool.get("name") != "SecurityKit" or not isinstance(data.get("findings"), list):
            continue
        reports.append((name, data))
    return reports


def finding_key(f):
    loc = f.get("location") or {}
    req = f.get("request") or {}
    return loc.get("file"), loc.get("line"), (req.get("method"), req.get("url")) if req else None


def same_issue(a, b):
    fa, la, ra = finding_key(a)
    fb, lb, rb = finding_key(b)
    if fa and fb:
        if fa != fb or la is None or lb is None or abs(la - lb) > LINE_SLACK:
            return False
    elif ra and rb:
        if ra != rb:
            return False
    else:
        return False
    cwe_a = set((a.get("references") or {}).get("cwe", []))
    cwe_b = set((b.get("references") or {}).get("cwe", []))
    return bool(cwe_a & cwe_b) or a.get("checkId") == b.get("checkId")


def merge(root, include_review, out_json, out_md):
    sk_dir = os.path.join(root, ".securitykit")
    warnings = []
    reports = load_reports(sk_dir, include_review, warnings)
    merged, per_skill = [], []
    for name, data in reports:
        skill = data["tool"].get("skill", name)
        per_skill.append({"skill": skill, "file": f".securitykit/{name}", "score": data.get("score"),
                          "generatedAt": data.get("generatedAt"), "summary": data.get("summary", {}),
                          "open": sum(1 for f in data["findings"] if not f.get("fixed"))})
        for f in data["findings"]:
            if f.get("fixed"):
                continue
            src = {"skill": skill, "id": f.get("id"), "checkId": f.get("checkId"), "severity": f.get("severity")}
            for m in merged:
                if same_issue(m["finding"], f):
                    m["sources"].append(src)
                    if SEVERITIES.index(f.get("severity", "Low")) < SEVERITIES.index(m["finding"].get("severity", "Low")):
                        m["finding"] = f
                    break
            else:
                merged.append({"finding": f, "sources": [src]})
    merged.sort(key=lambda m: (SEVERITIES.index(m["finding"].get("severity", "Low")), m["finding"].get("checkId", "")))
    findings = []
    for n, m in enumerate(merged, 1):
        f = m["finding"]
        findings.append({
            "id": f"SK-AUDIT-{n:04d}", "severity": f.get("severity"), "title": f.get("title"),
            "checkIds": sorted({s["checkId"] for s in m["sources"] if s.get("checkId")}),
            "location": f.get("location"), "request": f.get("request"),
            "evidence": f.get("evidence"), "impact": f.get("impact"), "fix": f.get("fix"),
            "regressionTest": f.get("regressionTest"), "references": f.get("references"),
            "sources": m["sources"],
        })
    counts = {s.lower(): sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    score = max(0, 100 - sum(WEIGHT[s] * counts[s.lower()] for s in SEVERITIES))
    total_in = sum(len(m["sources"]) for m in merged)
    result = {
        "schemaVersion": "1.0", "tool": {"name": "SecurityKit", "skill": "sk-audit", "version": VERSION},
        "generatedAt": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
        "score": score, "summary": {**counts, "skillsRun": len(per_skill), "findingsBeforeDedup": total_in,
                                    "duplicatesMerged": total_in - len(findings)},
        "skills": per_skill, "findings": findings, "warnings": warnings,
    }
    os.makedirs(os.path.dirname(os.path.abspath(out_json)), exist_ok=True)
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
        fh.write("\n")
    with open(out_md, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render_md(result, os.path.basename(os.path.abspath(root))))
    return result


def cell(s):
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")


def render_md(r, project):
    s = r["summary"]
    out = [
        "# Security Audit Report", "",
        f"**Project:** {project}  ",
        f"**Generated:** {r['generatedAt']} by SecurityKit sk-audit {VERSION}  ",
        f"**Skills combined:** {s['skillsRun']} · **Findings:** {s['findingsBeforeDedup']} reported, "
        f"{s['duplicatesMerged']} duplicates merged", "",
        f"## Overall score: {r['score']}/100", "",
        "| Critical | High | Medium | Low |", "|---:|---:|---:|---:|",
        f"| {s['critical']} | {s['high']} | {s['medium']} | {s['low']} |", "",
        "Score = 100 − 25×Critical − 10×High − 4×Medium − 1×Low over unique open findings (minimum 0).", "",
        "## Overview", "", "<!-- AGENT: 3-5 sentences: overall posture, the most important risks, what to fix first. -->", "",
        "## Results by skill", "",
        "| Skill | Score | Critical | High | Medium | Low | Open | Report generated |", "|---|---:|---:|---:|---:|---:|---:|---|",
    ]
    for k in sorted(r["skills"], key=lambda k: (k["score"] if isinstance(k["score"], int) else 101, k["skill"])):
        sm = k["summary"]
        out.append(f"| `/{k['skill']}` | {cell(k['score'])} | {sm.get('critical', 0)} | {sm.get('high', 0)} | "
                   f"{sm.get('medium', 0)} | {sm.get('low', 0)} | {k['open']} | {cell(k['generatedAt'])} |")
    out += ["", "## Findings", ""]
    for sev in SEVERITIES:
        out += [f"### {sev}", ""]
        group = [f for f in r["findings"] if f["severity"] == sev]
        if not group:
            out += ["None.", ""]
            continue
        out += ["| ID | Finding | Where | Checks | Found by |", "|---|---|---|---|---|"]
        for f in group:
            loc = f.get("location") or {}
            req = f.get("request") or {}
            where = f"`{loc['file']}:{loc['line']}`" if loc.get("file") else (f"`{req.get('method')} {req.get('url')}`" if req else "")
            out.append(f"| {f['id']} | {cell(f['title'])} | {where} | {', '.join(f['checkIds'])} | "
                       f"{', '.join(sorted({'/' + x['skill'] for x in f['sources']}))} |")
        out.append("")
    out += ["## Details", ""]
    for f in r["findings"]:
        out += [f"### {f['id']} · {f['severity']} · {cell(f['title'])}", "",
                f"**Checks:** {', '.join(f['checkIds'])} · **Found by:** {', '.join(sorted({x['skill'] for x in f['sources']}))}", "",
                f"**Evidence.** {f.get('evidence') or ''}", "", f"**Impact.** {f.get('impact') or ''}", "",
                f"**Fix.** {f.get('fix') or ''}", "", f"**Regression test.** {f.get('regressionTest') or ''}", ""]
    if r["warnings"]:
        out += ["## Warnings", ""] + [f"- {w}" for w in r["warnings"]] + [""]
    out += ["---", "", "Full details per finding are in each skill's report. Fix with `/sk-fix`; re-run `/sk-audit --merge-only` afterwards.", ""]
    return "\n".join(out)


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="SecurityKit audit helper.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan")
    p.add_argument("--root", default=".")
    p.add_argument("--skills-dir", default=os.path.join(here, "..", ".."))
    p.add_argument("--max-files", type=int, default=5000)
    p.add_argument("--out")
    m = sub.add_parser("merge")
    m.add_argument("--root", default=".")
    m.add_argument("--include-review", action="store_true", help="also merge the diff-scoped sk-review report")
    m.add_argument("--out", default=None, help="default: <root>/.securitykit/audit-report.json")
    m.add_argument("--md", default=None, help="default: <root>/security-report-audit.md")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)
    if args.cmd == "plan":
        result = plan(root, os.path.abspath(args.skills_dir), args.max_files)
        text = json.dumps(result, indent=2)
        if args.out:
            os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
            print(f"{len(result['run'])} skills to run -> {args.out}", file=sys.stderr)
        else:
            print(text)
        return 0
    out_json = args.out or os.path.join(root, ".securitykit", "audit-report.json")
    out_md = args.md or os.path.join(root, "security-report-audit.md")
    result = merge(root, args.include_review, out_json, out_md)
    s = result["summary"]
    print(f"score {result['score']}/100, {s['skillsRun']} reports, {len(result['findings'])} unique findings "
          f"({s['duplicatesMerged']} duplicates merged) -> {out_md}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

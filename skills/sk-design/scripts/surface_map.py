#!/usr/bin/env python3
"""
SecurityKit attack-surface mapper (static, read-only, standard library only).

Builds a language-agnostic inventory for design review and threat modeling:
  entry_points     HTTP routes, GraphQL, WebSockets, gRPC, queue consumers, scheduled jobs, uploads, webhooks
  admin            admin / internal / debug / metrics interfaces
  identity         authentication and authorization libraries and providers
  data_stores      databases, caches, search and vector stores, object storage
  external         third-party SDKs and outbound hosts
  ai               LLM / agent / embedding usage
  infra            containers, orchestration, IaC, CI/CD definitions
  config           environment variable *names* the code reads (never values)

Every item has file:line so the agent can verify it. Output is JSON (or a Markdown summary with --format md).
"""

import argparse
import json
import os
import re
import sys
from collections import OrderedDict

from sk_outputs import prepare_output

VERSION = "0.1.0"
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "target", "out", ".next", ".nuxt", "__pycache__",
             ".venv", "venv", "env", ".tox", ".securitykit", ".claude", ".codex", "coverage", ".idea", ".vscode",
             "bin", "obj", ".gradle", ".terraform", "site-packages"}
TEXT_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".rb", ".go", ".java", ".kt", ".cs", ".php", ".rs",
            ".scala", ".ex", ".exs", ".yml", ".yaml", ".json", ".toml", ".tf", ".proto", ".graphql", ".gql", ".xml",
            ".properties", ".env", ".ini", ".cfg", ".conf", ".sql"}
SPECIAL = re.compile(r"^(Dockerfile.*|Jenkinsfile.*|Procfile|Makefile|\.env.*)$")
MAX_BYTES = 1_500_000
CAP = 200  # items per category

R = lambda p: re.compile(p)

CATEGORIES = OrderedDict([
    ("entry_points", [
        ("http-route", R(r"""\b(app|router|api|routes|server|r|e|g|mux|bp|blueprint)\s*\.\s*(get|post|put|patch|delete|all|route|options|head|GET|POST|PUT|PATCH|DELETE|Any|HandleFunc|Handle)\s*\(\s*['"`](/[^'"`]*)""")),
        ("http-route", R(r"""@(app|router|api|bp|blueprint)\.(get|post|put|patch|delete|route|api_route)\(\s*['"]([^'"]*)""")),
        ("http-route", R(r"""@(Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(value\s*=\s*|path\s*=\s*)?\{?\s*"?([^")]*)""")),
        ("http-route", R(r"""\b(re_)?path\(\s*r?['"]([^'"]*)['"]\s*,""")),
        ("graphql", R(r"""\btype\s+(Query|Mutation|Subscription)\b|ApolloServer|graphqlHTTP|GraphQLModule|strawberry\.Schema|graphene\.Schema""")),
        ("websocket", R(r"""new\s+WebSocketServer|ws\.Server|socket\.io|@WebSocketGateway|websockets\.serve|@app\.websocket|upgrader\.Upgrade|SignalR|ActionCable""")),
        ("grpc", R(r"""^\s*service\s+\w+\s*\{|grpc\.Server\(|NewServer\(\)\s*//\s*grpc|@GrpcService|grpc\.server\(""")),
        ("queue-consumer", R(r"""\.subscribe\(|\.consume\(|@KafkaListener|@RabbitListener|@SqsListener|ReceiveMessage|kafka\.Consumer|amqp\.|pubsub|@celery\.task|@shared_task|\.process\(\s*['"]|new\s+Worker\(""")),
        ("scheduled-job", R(r"""cron\.schedule|node-cron|@Scheduled|apscheduler|schedule\.every|@periodic_task|crontab\(|CronJob|setInterval\(""")),
        ("file-upload", R(r"""multer\(|UploadFile|request\.files|MultipartFile|formidable|busboy|IFormFile|\$_FILES""")),
        ("webhook", R(r"""['"`][^'"`\s]*/(webhooks?|hooks?|callbacks?|ipn)\b[^'"`\s]*['"`]""")),
    ]),
    ("admin", [
        ("admin-interface", R(r"""['"`][^'"`\s]*/(admin|internal|debug|metrics|actuator|_debug|pprof|management|console|graphiql|playground|swagger|api-docs)\b[^'"`\s]*['"`]|admin\.site\.urls|management\.endpoints|net/http/pprof|debug_toolbar""")),
    ]),
    ("identity", [
        ("auth-library", R(r"""\b(passport|next-auth|@auth/|jsonwebtoken|\bjose\b|express-session|cookie-session|oauth2?|openid|oidc|saml|devise|omniauth|spring-security|SecurityFilterChain|django\.contrib\.auth|rest_framework\.permissions|flask_login|flask_jwt|fastapi\.security|auth0|cognito|keycloak|@clerk/|firebase-admin|supabase\.auth|lucia|better-auth|casbin|oso|cerbos|permit\.io)\b""")),
    ]),
    ("data_stores", [
        ("database", R(r"""\b(pg|postgres|psycopg2?|asyncpg|mysql2?|mariadb|mongodb|mongoose|sequelize|prisma|typeorm|knex|drizzle|sqlalchemy|django\.db|gorm|database/sql|jdbc:|hibernate|EntityFramework|DbContext|sqlite3?|dynamodb|firestore|cosmos|cassandra|neo4j|couchdb)\b""")),
        ("cache-queue", R(r"""\b(redis|ioredis|memcached|kafka|rabbitmq|amqplib|nats|sqs|sns|pubsub|bullmq|bull)\b""")),
        ("search-vector", R(r"""\b(elasticsearch|opensearch|meilisearch|typesense|algolia|pinecone|qdrant|weaviate|chroma(db)?|milvus|pgvector|faiss|lancedb)\b""")),
        ("object-storage", R(r"""\b(s3|S3Client|aws_s3_bucket|google-cloud-storage|@google-cloud/storage|BlobServiceClient|azure-storage|minio|r2)\b""")),
    ]),
    ("external", [
        ("sdk", R(r"""\b(stripe|paypal|braintree|adyen|twilio|sendgrid|mailgun|postmark|resend|nodemailer|slack|discord|github|octokit|gitlab|shopify|hubspot|salesforce|zendesk|intercom|segment|mixpanel|amplitude|posthog|sentry|datadog|newrelic|launchdarkly|cloudinary|mapbox|plaid|firebase|supabase|aws-sdk|boto3|@aws-sdk|google-cloud|googleapis|@azure)\b""")),
        ("outbound-host", R(r"""https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|example\.(com|org)|www\.w3\.org|json-schema\.org|schemas\.|github\.com/getsecuritykit)([a-z0-9][\w.-]+\.[a-z]{2,})""")),
    ]),
    ("ai", [
        ("llm", R(r"""\b(openai|anthropic|langchain|langgraph|llama_index|llamaindex|@ai-sdk|ai/react|ollama|huggingface|transformers|sentence_transformers|cohere|mistralai|google\.generativeai|vertexai|bedrock|semantic_kernel|autogen|crewai|mcp)\b""")),
    ]),
    ("infra", [
        ("container", R(r"""^\s*FROM\s+\S+|^\s*services\s*:\s*$""")),
        ("kubernetes", R(r"""^\s*kind\s*:\s*(Deployment|StatefulSet|DaemonSet|Service|Ingress|CronJob|Job|Pod|NetworkPolicy|Role|ClusterRole)\b""")),
        ("terraform", R(r"""^\s*resource\s+"(\w+)"\s+"(\w+)"|^\s*provider\s+"(\w+)\"""")),
        ("ci-cd", R(r"""^\s*on\s*:|^\s*stages\s*:|pipeline\s*\{|^\s*workflows\s*:""")),
    ]),
])
ENV_NAME = re.compile(r"""process\.env\.([A-Z][A-Z0-9_]{2,})|process\.env\[['"]([A-Z][A-Z0-9_]{2,})['"]\]|os\.environ(?:\.get)?\(?\[?\s*['"]([A-Z][A-Z0-9_]{2,})['"]|os\.getenv\(\s*['"]([A-Z][A-Z0-9_]{2,})['"]|System\.getenv\(\s*"([A-Z][A-Z0-9_]{2,})"|os\.Getenv\(\s*"([A-Z][A-Z0-9_]{2,})"|ENV\[['"]([A-Z][A-Z0-9_]{2,})['"]\]|import\.meta\.env\.([A-Z][A-Z0-9_]{2,})""")


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not (d.startswith(".") and d not in (".github", ".gitlab", ".circleci")))
        for f in sorted(filenames):
            if os.path.splitext(f)[1].lower() not in TEXT_EXT and not SPECIAL.match(f):
                continue
            if f.endswith((".min.js", ".lock")) or f in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
                continue
            full = os.path.join(dirpath, f)
            try:
                if os.path.getsize(full) > MAX_BYTES:
                    continue
                with open(full, encoding="utf-8", errors="replace") as fh:
                    yield os.path.relpath(full, root).replace(os.sep, "/"), fh.read().splitlines()
            except OSError:
                continue


def scan(root):
    out = OrderedDict((k, []) for k in list(CATEGORIES) + ["config"])
    seen = set()
    env_names = OrderedDict()
    for rel, lines in walk(root):
        is_test = bool(re.search(r"(^|/)(tests?|__tests__|spec|e2e|fixtures?)/|\.(test|spec)\.", rel))
        for i, line in enumerate(lines, start=1):
            if len(line) > 2000:
                continue
            for cat, patterns in CATEGORIES.items():
                for kind, rx in patterns:
                    m = rx.search(line)
                    if not m:
                        continue
                    name = next((g for g in reversed(m.groups()) if g), m.group(0)).strip()[:120] if m.groups() else m.group(0).strip()[:120]
                    key = (cat, kind, name.lower()) if kind in ("sdk", "auth-library", "database", "cache-queue", "search-vector", "object-storage", "llm", "outbound-host") else (cat, kind, rel, i)
                    if key in seen or len(out[cat]) >= CAP:
                        continue
                    seen.add(key)
                    out[cat].append({"kind": kind, "name": name, "file": rel, "line": i, "test": is_test})
            for m in ENV_NAME.finditer(line):
                name = next(g for g in m.groups() if g)
                env_names.setdefault(name, {"kind": "env-var", "name": name, "file": rel, "line": i})
    out["config"] = list(env_names.values())[:CAP]
    summary = {k: len(v) for k, v in out.items()}
    return {"tool": "securitykit-surface-map", "version": VERSION, "root": ".", "summary": summary, "surface": out}


def to_markdown(result):
    lines = ["# Attack surface map", ""]
    for cat, items in result["surface"].items():
        lines.append(f"## {cat.replace('_', ' ').title()} ({len(items)})")
        lines.append("")
        if not items:
            lines.append("None found.")
        for it in items[:60]:
            lines.append(f"- `{it['kind']}` **{it['name']}** ({it['file']}:{it['line']}){' (test)' if it.get('test') else ''}")
        if len(items) > 60:
            lines.append(f"- … {len(items) - 60} more in the JSON output")
        lines.append("")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Map a project's attack surface (SecurityKit).")
    ap.add_argument("--root", default=".")
    ap.add_argument("--format", choices=["json", "md"], default="json")
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    if not os.path.isdir(args.root):
        print(f"error: not a directory: {args.root}", file=sys.stderr)
        return 2
    result = scan(args.root)
    text = json.dumps(result, indent=2) if args.format == "json" else to_markdown(result)
    if args.out:
        prepare_output(args.out)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"surface: {result['summary']} -> {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
SecurityKit GraphQL surface finder (static, read-only, standard library only).

Language-agnostic: looks for GraphQL *concepts* (schemas, operations, server setup, and the
controls for introspection, depth, cost, batching, error masking, CSRF and authorization) using
text signals that appear in any stack. Prints JSON:

  { "endpoints", "servers", "schema_sources", "operations": {query, mutation, subscription},
    "types", "signals": {concept: [hits]}, "candidates": [ {check_id, title, file, line, snippet,
    confidence, note} ], "warnings" }

Every candidate is a lead for the agent to confirm or reject by reading the code. A missing
control ("no depth limit found") is reported at the server construction site when one is found.
"""

import argparse
import bisect
import json
import os
import re
import sys

from sk_outputs import prepare_output

VERSION = "0.1.0"

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "target", "out", ".next", ".nuxt", "__pycache__",
    ".venv", "venv", "env", ".tox", ".securitykit", ".claude", ".codex", "coverage", ".idea", ".vscode",
    "bin", "obj", "Pods", ".gradle",
}
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "testdata", "e2e"}
TEST_FILE_RE = re.compile(r"(\.(test|spec)\.[cm]?[jt]sx?$)|(^test_.*\.py$)|(_test\.(py|go)$)|(Tests?\.(java|kt|cs)$)|(_spec\.rb$)")
CODE_EXT = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx", ".py", ".rb", ".go", ".java", ".kt",
            ".cs", ".php", ".ex", ".exs", ".scala", ".rs", ".yml", ".yaml", ".json", ".properties", ".toml"}
SDL_EXT = {".graphql", ".gql", ".graphqls"}
MAX_BYTES = 1_500_000

# --------------------------------------------------------------------------- concept signals
# Library names appear only as detection hints; the checks themselves are about the concept.

SERVER = re.compile(
    r"ApolloServer\b|new\s+ApolloGateway|graphqlHTTP\s*\(|createHandler\s*\(|createYoga\s*\(|mercurius|"
    r"GraphQLModule\.forRoot|buildSchema\s*\(|makeExecutableSchema|"
    r"strawberry\.(asgi|fastapi|django|flask|aiohttp)|GraphQLRouter\s*\(|GraphQLView|graphene_django|"
    r"ariadne\.(asgi|wsgi)|make_executable_schema|graphene\.Schema\s*\(|strawberry\.Schema\s*\(|"
    r"handler\.NewDefaultServer|handler\.New\s*\(|graphql\.MustParseSchema|graphql\.NewSchema|"
    r"GraphQL\.newGraphQL|spring\.graphql|@EnableDgs|DgsComponent|"
    r"AddGraphQLServer\s*\(|MapGraphQL\s*\(|GraphQL::Schema|Absinthe\.Plug|Lighthouse|webonyx|"
    r"async_graphql::Schema|juniper::RootNode"
)
ENDPOINT = re.compile(r"""['"`](/[\w./-]*graphql[\w./-]*)['"`]""", re.I)

SIGNALS = {
    "introspection_on": r"introspection\s*[:=]\s*(true|True)\b|IntrospectionEnabled\s*=\s*true|introspection\.enabled\s*[:=]\s*true",
    "introspection_off": (
        r"introspection\s*[:=]\s*(false|False)\b|NoSchemaIntrospectionCustomRule|DisableIntrospection|"
        r"disable_introspection|introspection\s*[:=][^,\n}]*(env|ENV|production|PROD|isDev|DEBUG|debug)|"
        r"AllowIntrospection\s*\(\s*false|introspection\.enabled\s*[:=]\s*false|DisableIntrospection\(\)|"
        r"NoIntrospection|introspection:\s*!|IntrospectionDisabled|disableIntrospection"
    ),
    "ide_on": (
        r"(graphiql|playground)\s*[:=]\s*(true|True)\b|ApolloServerPluginLandingPage(GraphQLPlayground|LocalDefault)|"
        r"graphiql\s*=\s*True|playground\.Handler|GraphiQL\s*\(|UseGraphQLPlayground|graphql_ide\s*=\s*['\"]"
    ),
    "depth_limit": (
        r"depth[-_ ]?limit|depthLimit|max_?depth|maxDepth|MaxDepth|QueryDepthLimiter|DepthLimitRule|"
        r"MaxQueryDepth|max_query_depth|AddMaxExecutionDepthRule|maxQueryDepth|MaxDepthPlugin|depth_limit"
    ),
    "cost_limit": (
        r"complexity|costAnalysis|cost[-_]analysis|query[-_]?cost|maxCost|max_cost|FixedComplexityLimit|"
        r"MaxQueryComplexity|max_complexity|createComplexityRule|@cost\b|MaxComplexity|ComplexityLimit|"
        r"QueryComplexity|complexity_limit|maxComplexity"
    ),
    "batching_on": (
        r"allowBatchedHttpRequests\s*:\s*true|batching\s*[:=]\s*(true|True)|\bbatch\s*:\s*true|"
        r"allowBatchedQueries|enableBatching|batchEnabled|BatchingEnabled\s*=\s*true|batch\s*=\s*True"
    ),
    "batch_limit": r"maxBatch|batchLimit|max_batch|maxOperations|max_operations|batch[-_ ]?size[-_ ]?limit",
    "alias_limit": r"maxAliases|max_aliases|alias[-_ ]?limit|MaxAliases|maxRootFields|max_root_fields|maxDirectives",
    "errors_verbose": (
        r"includeStacktraceInErrorResponses\s*:\s*true|\bdebug\s*[:=]\s*(true|True)\b|maskedErrors\s*:\s*false|"
        r"mask_errors\s*=\s*False|IncludeExceptionDetails\s*=\s*true|exposeExceptions|expose_exceptions"
    ),
    "errors_masked": (
        r"formatError|maskedErrors|MaskErrors|mask_errors|error_formatter|SetErrorPresenter|ErrorFilter|"
        r"maskError|DataFetcherExceptionResolver|handle_errors|process_errors|format_error"
    ),
    "csrf_off": r"csrfPrevention\s*:\s*false",
    "csrf_on": r"csrfPrevention\s*:\s*true|requirePreflight|apollo-require-preflight|x-csrf-token|csrf_protect|CsrfViewMiddleware",
    "get_allowed": r"allowGetRequests|allowedRequestMethods|useGETForQueries|GET\s+/graphql|\.get\(\s*['\"][^'\"]*graphql|methods\s*[:=]\s*\[[^\]]*['\"]GET",
    "persisted": r"persistedQueries|persisted_queries|automaticPersistedQueries|usePersistedOperations|trustedDocuments|operation[-_ ]?allow[-_ ]?list|safelist",
    "context_auth": r"context\s*[:=(][\s\S]{0,200}?(authorization|Authorization|token|getUser|currentUser|current_user|verify|jwt|session)",
    "field_auth": (
        r"@(auth|authenticated|hasRole|hasScope|requiresScopes|policy|isAuthenticated|private|requireAuth|"
        r"authorized|Authorize|PreAuthorize|Secured|RolesAllowed|permission|permissions|IsAuthenticated|requires)\b|"
        r"graphql-shield|\bshield\s*\(|permission_classes|@Authorized|authChecker|FieldMiddleware|"
        r"directiveResolvers|AuthorizeDirective|has_permission|PermissionExtension|GuardedField|UseGuards"
    ),
    "subscriptions": r"type\s+Subscription\b|@Subscription\b|graphql-ws|subscriptions-transport-ws|useServer\s*\(|SubscriptionServer|subscriptions\s*:",
    "ws_auth": r"onConnect|connectionParams|on_connect|connection_init|InitFunc|WebsocketInitFunc|onSubscribe",
    "federation": r"buildSubgraphSchema|buildFederatedSchema|@apollo/subgraph|_entities|_service\b|federation\s*[:=]|enable_federation|@key\s*\(",
    "body_limit": r"(json|bodyParser)[^\n]{0,40}limit\s*:|maxBodySize|max_body_size|MaxBytesReader|client_max_body_size|DATA_UPLOAD_MAX_MEMORY_SIZE|maxTokens|max_tokens",
    "timeout": r"(execution|query|request)[-_ ]?timeout|timeoutMs|timeout\s*[:=]",
    "validation_disabled": r"validationRules\s*:\s*\[\s*\]|validate\s*:\s*false|skipValidation|disable_validation|validation_rules\s*=\s*\[\s*\]",
}
SIGNALS = {k: re.compile(v) for k, v in SIGNALS.items()}

CODE_FIRST_OPS = re.compile(
    r"@(Query|Mutation|Subscription)\s*\(|@strawberry\.(mutation|subscription)|"
    r"@(QueryMapping|MutationMapping|SubscriptionMapping)\b|"
    r"func\s*\(\s*\w+\s*\*(query|mutation|subscription)Resolver\)\s*(\w+)|"
    r"\b(Query|Mutation|Subscription)\s*:\s*\{"
)

SENSITIVE_FIELD = re.compile(
    r"^(password\w*|passwd|pass_?hash|\w*secret\w*|\w*token\w*|api_?key\w*|ssn|social_?security\w*|tax_?id|"
    r"salary|dob|date_?of_?birth|birth_?date|credit_?card\w*|card_?number|cvv|iban|account_?number|bank\w*|"
    r"phone\w*|email\w*|address\w*|role|roles|permissions?|is_?admin|is_?staff|internal\w*|private\w*|"
    r"mfa\w*|otp\w*|two_?factor\w*|hash\w*|ip_?address|last_?login_?ip)$",
    re.I,
)
PROTECTED_INPUT = re.compile(
    r"^(role|roles|is_?admin|admin|is_?staff|permissions?|owner_?id|user_?id|account_?id|tenant_?id|org_?id|"
    r"organization_?id|balance|credits?|verified|is_?verified|email_?verified|status|plan|tier|price|"
    r"discount|approved|is_?approved|created_?by|created_?at)$",
    re.I,
)
PRIVILEGED_MUTATION = re.compile(
    r"delete|remove|destroy|purge|admin|role|grant|revoke|promote|demote|ban|suspend|impersonate|refund|"
    r"transfer|approve|setPrice|set_price|updateUser|update_user|createUser|create_user|invite|resetPassword|"
    r"reset_password|changeEmail|change_email|export|import|migrate|config|settings",
    re.I,
)
PAGINATION_ARGS = {"first", "last", "limit", "take", "pagesize", "page_size", "perpage", "per_page", "count", "size", "max"}
AUTH_DIRECTIVE = re.compile(
    r"@(auth|authenticated|hasRole|hasScope|requiresScopes|policy|isAuthenticated|private|requireAuth|"
    r"authorized|requires|permission|permissions|aws_auth|aws_cognito_user_pools|aws_iam)\b", re.I)


# --------------------------------------------------------------------------- helpers

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
            if not include_tests and TEST_FILE_RE.search(f):
                continue
            ext = os.path.splitext(f)[1].lower()
            if ext not in CODE_EXT and ext not in SDL_EXT:
                continue
            full = os.path.join(dirpath, f)
            try:
                if os.path.getsize(full) > MAX_BYTES:
                    continue
                with open(full, encoding="utf-8", errors="replace") as fh:
                    yield full, fh.read()
            except OSError:
                continue


def strip_sdl_noise(sdl):
    """Remove comments and descriptions, keeping offsets (replaced by spaces)."""
    def blank(m):
        return re.sub(r"[^\n]", " ", m.group(0))
    sdl = re.sub(r'"""[\s\S]*?"""', blank, sdl)
    sdl = re.sub(r'(?m)^\s*"[^"\n]*"\s*$', blank, sdl)
    sdl = re.sub(r"#[^\n]*", blank, sdl)
    return sdl


TYPE_RE = re.compile(r"\b(?:extend\s+)?(type|input|interface)\s+(\w+)[^{}]*?\{([^{}]*)\}")
# name(args): Type @directive(...)  -- trailing part is directives only, so one-line bodies parse every field
FIELD_RE = re.compile(r"(\w+)\s*(\([^()]*\))?\s*:\s*([\[\]\w!]+)((?:\s*@\w+(?:\([^()]*\))?)*)")


def parse_sdl(sdl, base_line, file, types):
    """Parse type/input/interface definitions out of SDL text into `types`."""
    clean = strip_sdl_noise(sdl)
    idx = LineIndex(clean)
    for tm in TYPE_RE.finditer(clean):
        kind, name, body = tm.group(1), tm.group(2), tm.group(3)
        body_start = tm.start(3)
        t = types.setdefault(name, {"kind": kind, "file": file, "line": base_line + idx.line(tm.start()) - 1, "fields": []})
        for fm in FIELD_RE.finditer(body):
            fname, args, ftype, rest = fm.group(1), fm.group(2) or "", fm.group(3), fm.group(4)
            arg_names = re.findall(r"(\w+)\s*:", args)
            arg_types = dict(re.findall(r"(\w+)\s*:\s*([\[\]\w!]+)", args))
            t["fields"].append({
                "name": fname,
                "args": arg_names,
                "arg_types": arg_types,
                "type": ftype.replace("!", "").strip("[]"),
                "list": ftype.lstrip().startswith("["),
                "directives": re.findall(r"@\w+", rest),
                "file": file,
                "line": base_line + idx.line(body_start + fm.start()) - 1,
            })


IMPORT_LINE = re.compile(r"^(import\b|from\s+\S+\s+import\b|using\b|require\b|package\b|const\s*\{[^}]*\}\s*=\s*require\()")
EMBEDDED_SDL = re.compile(r"`([^`]*)`|\"\"\"([\s\S]*?)\"\"\"|'''([\s\S]*?)'''")
LOOKS_SDL = re.compile(r"\b(type|extend\s+type|input|interface)\s+\w+[^{}\n]*\{")


def line_text(text, line):
    lines = text.splitlines()
    return lines[line - 1].strip()[:200] if 0 < line <= len(lines) else ""


# --------------------------------------------------------------------------- main scan

def scan(root, include_tests=False):
    root = os.path.abspath(root)
    rel = lambda p: os.path.relpath(p, root).replace(os.sep, "/")
    types = {}
    schema_sources, servers, endpoints, code_first = [], [], [], []
    signals = {k: [] for k in SIGNALS}
    texts = {}
    warnings = []

    for path, text in walk(root, include_tests):
        r = rel(path)
        ext = os.path.splitext(path)[1].lower()
        idx = LineIndex(text)
        if ext in SDL_EXT:
            schema_sources.append({"file": r, "line": 1, "kind": "sdl-file"})
            parse_sdl(text, 1, r, types)
            texts[r] = text
            for k, rx in SIGNALS.items():
                for m in rx.finditer(text):
                    signals[k].append({"file": r, "line": idx.line(m.start()), "match": m.group(0)[:80]})
            continue
        if "graphql" not in text.lower() and "gql" not in text and not SERVER.search(text):
            continue
        texts[r] = text
        for m in EMBEDDED_SDL.finditer(text):
            body = next(g for g in m.groups() if g is not None)
            if LOOKS_SDL.search(body) and re.search(r"\b(Query|Mutation|Subscription)\b", body):
                line = idx.line(m.start())
                schema_sources.append({"file": r, "line": line, "kind": "embedded-sdl"})
                parse_sdl(body, line, r, types)
        for m in SERVER.finditer(text):
            line = idx.line(m.start())
            if IMPORT_LINE.match(line_text(text, line)):
                continue  # an import, not the construction site
            servers.append({"file": r, "line": line, "match": m.group(0)[:60]})
        for m in ENDPOINT.finditer(text):
            endpoints.append({"path": m.group(1), "file": r, "line": idx.line(m.start())})
        for m in CODE_FIRST_OPS.finditer(text):
            code_first.append({"file": r, "line": idx.line(m.start()), "match": m.group(0)[:60]})
        for k, rx in SIGNALS.items():
            for m in rx.finditer(text):
                signals[k].append({"file": r, "line": idx.line(m.start()), "match": m.group(0)[:80]})

    def ops(kind):
        out = []
        for tname in (kind.capitalize(),):
            t = types.get(tname)
            if t:
                for f in t["fields"]:
                    out.append({"name": f["name"], "args": f["args"], "returns": f["type"], "list": f["list"],
                                "directives": f["directives"], "file": f["file"], "line": f["line"]})
        return out

    operations = {"query": ops("query"), "mutation": ops("mutation"), "subscription": ops("subscription")}
    candidates = build_candidates(types, operations, servers, signals, texts)
    if not servers and not types and not code_first:
        warnings.append("no GraphQL server, schema or resolvers found")
    elif not types and code_first:
        warnings.append("code-first schema: operations listed from resolver declarations; read them to build the inventory")

    seen = set()
    endpoints = [e for e in endpoints if not (e["path"] in seen or seen.add(e["path"]))]
    return {
        "tool": "securitykit-find-graphql",
        "version": VERSION,
        "root": ".",
        "endpoints": endpoints,
        "servers": servers,
        "schema_sources": schema_sources,
        "code_first_operations": code_first,
        "operations": operations,
        "types": {k: {"kind": v["kind"], "file": v["file"], "line": v["line"],
                      "fields": [f["name"] for f in v["fields"]]} for k, v in sorted(types.items())},
        "signals": {k: v for k, v in signals.items() if v},
        "candidates": candidates,
        "warnings": warnings,
    }


def build_candidates(types, operations, servers, signals, texts):
    out = []

    def add(check_id, title, file, line, confidence, note):
        out.append({"check_id": check_id, "title": title, "file": file, "line": line,
                    "snippet": line_text(texts.get(file, ""), line) if file else "",
                    "confidence": confidence, "note": note})

    site = servers[0] if servers else None
    has = lambda k: bool(signals.get(k))

    def at_site(check_id, title, confidence, note):
        if site:
            add(check_id, title, site["file"], site["line"], confidence, note)
        else:
            add(check_id, title, None, None, "LOW", note + " (server construction not found: locate it manually)")

    # Introspection / IDE
    for hit in signals["introspection_on"]:
        add("GQL-INTRO-001", "Introspection explicitly enabled", hit["file"], hit["line"], "HIGH",
            "Confirm this is not active in production")
    if not has("introspection_on") and not has("introspection_off") and (servers or types):
        at_site("GQL-INTRO-001", "No introspection control found", "MEDIUM",
                "Many servers enable introspection by default; check the library default and environment")
    for hit in signals["ide_on"]:
        add("GQL-INTRO-003", "Interactive GraphQL IDE enabled", hit["file"], hit["line"], "MEDIUM",
            "Confirm it is disabled in production")

    # Limits
    if (servers or types) and not has("depth_limit"):
        at_site("GQL-DOS-001", "No query depth limit found", "MEDIUM", "No depth-limiting rule or setting found anywhere")
    if (servers or types) and not has("cost_limit"):
        at_site("GQL-DOS-002", "No query cost / complexity limit found", "MEDIUM", "No cost analysis found anywhere")
    for hit in signals["validation_disabled"]:
        add("GQL-DOS-005", "GraphQL validation rules disabled or emptied", hit["file"], hit["line"], "HIGH", "")
    if (servers or types) and not has("body_limit"):
        at_site("GQL-DOS-004", "No request size limit found", "LOW", "Check HTTP layer / proxy limits too")

    # Batching
    for hit in signals["batching_on"]:
        if not has("batch_limit"):
            add("GQL-BATCH-001", "Array batching enabled without a visible cap", hit["file"], hit["line"], "MEDIUM", "")
    if (servers or types) and not has("alias_limit") and not has("cost_limit"):
        at_site("GQL-BATCH-002", "No alias / root-field limit found", "LOW",
                "One request may call the same field many times via aliases; matters most for login/OTP/redeem mutations")

    # Errors
    for hit in signals["errors_verbose"]:
        add("GQL-ERR-001", "Verbose errors / debug enabled", hit["file"], hit["line"], "MEDIUM",
            "Confirm this is tied to a non-production environment")
    if (servers or types) and not has("errors_masked"):
        at_site("GQL-ERR-001", "No error masking / formatter found", "LOW", "Check the library default for production error output")

    # CSRF
    for hit in signals["csrf_off"]:
        add("GQL-CSRF-001", "CSRF prevention explicitly disabled", hit["file"], hit["line"], "HIGH",
            "Matters when auth uses cookies")

    # Authentication / subscriptions / federation
    if (servers or types) and not has("context_auth"):
        at_site("GQL-AUTHN-001", "No authentication in request context found", "LOW",
                "Find where the caller is identified; if nowhere, every operation is anonymous")
    sub_ops = operations["subscription"]
    if (sub_ops or has("subscriptions")) and not has("ws_auth"):
        loc = sub_ops[0] if sub_ops else signals["subscriptions"][0]
        add("GQL-AUTHN-002", "Subscriptions without visible connection authentication", loc["file"], loc["line"],
            "LOW", "Check the WebSocket connect handler and per-event filtering")
    for hit in signals["federation"][:3]:
        add("GQL-ARCH-001", "Federation / subgraph surface", hit["file"], hit["line"], "LOW",
            "Confirm subgraphs are reachable only from the gateway")

    # Schema-driven authorization leads
    any_field_auth = has("field_auth")
    reverse = {}  # type name -> [(parent type, field)]
    for tname, t in types.items():
        if t["kind"] != "type":
            continue
        for f in t["fields"]:
            reverse.setdefault(f["type"], []).append((tname, f["name"]))

    for tname, t in sorted(types.items()):
        if t["kind"] == "input":
            for f in t["fields"]:
                if PROTECTED_INPUT.match(f["name"]):
                    add("GQL-AUTHZ-005", f"Input {tname}.{f['name']} may set a protected field", f["file"], f["line"],
                        "MEDIUM", "Confirm only privileged callers can set it")
            continue
        if tname in ("Query", "Mutation", "Subscription"):
            continue
        for f in t["fields"]:
            if SENSITIVE_FIELD.match(f["name"]) and not any(AUTH_DIRECTIVE.match(d) for d in f["directives"]):
                parents = [f"{p}.{pf}" for p, pf in reverse.get(tname, [])]
                add("GQL-AUTHZ-002", f"Sensitive field {tname}.{f['name']}", f["file"], f["line"],
                    "MEDIUM" if not any_field_auth else "LOW",
                    f"Reachable via {len(parents)} parent field(s): {', '.join(parents[:8]) or 'root only'}. "
                    "Confirm a field- or data-layer guard applies on every path")
            if f["list"] and not ({a.lower() for a in f["args"]} & PAGINATION_ARGS):
                add("GQL-DOS-003", f"Unpaginated list field {tname}.{f['name']}", f["file"], f["line"], "LOW",
                    "Confirm the resolver bounds the result size")

    for op in operations["query"]:
        id_args = [a for a in op["args"] if a.lower() in ("id", "ids") or a.lower().endswith("id")]
        if id_args or op["name"] in ("node", "nodes"):
            add("GQL-AUTHZ-001" if op["name"] not in ("node", "nodes") else "GQL-AUTHZ-004",
                f"Query {op['name']}({', '.join(id_args)}) loads by ID", op["file"], op["line"], "MEDIUM",
                "Confirm the resolver scopes the lookup to the caller (owner/tenant)")
        if op["list"] and not ({a.lower() for a in op["args"]} & PAGINATION_ARGS):
            add("GQL-DOS-003", f"Unpaginated list query {op['name']}", op["file"], op["line"], "MEDIUM",
                "Confirm the resolver bounds the result size")
    for op in operations["mutation"]:
        if PRIVILEGED_MUTATION.search(op["name"]):
            add("GQL-AUTHZ-003", f"Privileged mutation {op['name']}", op["file"], op["line"], "MEDIUM",
                "Confirm a role/permission check in the resolver or service layer")
        if re.search(r"login|signin|sign_in|otp|verify|reset|redeem|coupon|2fa|mfa", op["name"], re.I):
            add("GQL-BATCH-002", f"Brute-forceable mutation {op['name']}", op["file"], op["line"], "MEDIUM",
                "Confirm rate limits count each aliased call, not each HTTP request")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Find the GraphQL surface and missing controls (SecurityKit).")
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", help="write JSON here instead of stdout")
    ap.add_argument("--include-tests", action="store_true")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)
    if not os.path.isdir(args.root):
        print(f"error: not a directory: {args.root}", file=sys.stderr)
        return 2
    result = scan(args.root, args.include_tests)
    text = json.dumps(result, indent=2)
    if args.out:
        prepare_output(args.out)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"{len(result['candidates'])} candidates -> {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
SecurityKit GraphQL probes (optional, dynamic, standard library only).

Sends a small set of read-only GraphQL requests to an endpoint and records candidates with the
exact request and response excerpt as evidence:

  introspection (GQL-INTRO-001) · field suggestions (GQL-INTRO-002) · array batching (GQL-BATCH-001)
  alias batching (GQL-BATCH-002) · depth limit (GQL-DOS-001) · error verbosity (GQL-ERR-001)
  GET / simple-content-type execution, i.e. CSRF exposure (GQL-CSRF-001) · anonymous access (GQL-AUTHN-001)

Safety: localhost only unless --i-own-this-host; only queries plus `mutation { __typename }`
(which has no side effects); request budget; tokens redacted from output.
"""

import argparse
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

VERSION = "0.1.0"
EXCERPT = 500
STACK_RE = re.compile(
    r"stacktrace|\"exception\"|Traceback \(most recent call last\)|at [\w$.<>]+ \(.*?:\d+:\d+\)|"
    r"\.(js|ts|py|go|java|rb|cs):\d+|java\.lang\.|goroutine \d+|SQLSTATE|SequelizeDatabaseError",
    re.I,
)

INTROSPECTION = """query SkIntrospection { __schema { queryType { name } mutationType { name }
  types { name kind fields(includeDeprecated: true) { name args { name type { kind name ofType { kind name ofType { kind name } } } }
  type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"""


def is_local(host):
    host = (host or "").strip("[]").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Client:
    def __init__(self, url, token, auth_header, budget, timeout):
        self.url, self.token, self.auth_header = url, token, auth_header
        self.budget, self.timeout, self.sent = budget, timeout, 0
        self.use_token = False
        self.opener = urllib.request.build_opener(NoRedirect)

    def redact(self, s):
        return s.replace(self.token, self.token[:4] + "…") if self.token and len(self.token) > 4 else s

    def send(self, method="POST", body=None, content_type="application/json", query_string=None, raw=None):
        if self.sent >= self.budget:
            raise RuntimeError("request budget exhausted")
        self.sent += 1
        url = self.url + ("?" + query_string if query_string else "")
        headers = {"User-Agent": f"SecurityKit-sk-graphql/{VERSION}", "Accept": "application/json"}
        data = None
        if method == "POST":
            data = raw if raw is not None else json.dumps(body).encode()
            headers["Content-Type"] = content_type
        if self.use_token and self.token:
            name, _, tmpl = self.auth_header.partition(":")
            headers[name.strip()] = tmpl.strip().replace("{token}", self.token)
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            resp = self.opener.open(req, timeout=self.timeout)
            status, text = resp.status, resp.read(256 * 1024).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status, text = e.code, (e.read(256 * 1024).decode("utf-8", "replace") if e.fp else "")
        except (urllib.error.URLError, OSError) as e:
            return {"status": 0, "error": str(e), "text": "", "json": None, "url": url, "method": method}
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        sent_body = (data or b"").decode("utf-8", "replace")
        return {"status": status, "text": text, "json": parsed, "url": url, "method": method,
                "requestExcerpt": self.redact(f"{method} {url}\nContent-Type: {headers.get('Content-Type', '-')}\n\n{sent_body[:400]}")}


def has_data(r, key=None):
    j = r.get("json")
    if isinstance(j, dict) and isinstance(j.get("data"), dict):
        return key is None or key in j["data"]
    return False


def unwrap(t):
    while t and t.get("ofType") and t.get("kind") in ("NON_NULL", "LIST"):
        t = t["ofType"]
    return t or {}


def required_args(field):
    return [a for a in field.get("args") or [] if (a.get("type") or {}).get("kind") == "NON_NULL"]


def find_cycle_path(types, root, depth):
    """Build a selection that follows object fields without required args, to `depth` levels."""
    objects = {t["name"]: t for t in types if t.get("kind") == "OBJECT" and not t["name"].startswith("__")}

    def children(tname):
        out = []
        for f in (objects.get(tname, {}).get("fields") or []):
            inner = unwrap(f["type"])
            if inner.get("kind") == "OBJECT" and inner.get("name") in objects and not required_args(f):
                out.append((f["name"], inner["name"]))
        return out

    # DFS for a path that revisits a type (a cycle), so depth is unbounded by the schema itself.
    best = None
    stack = [(root, [], [root])]
    while stack:
        tname, path, seen = stack.pop()
        for fname, child in children(tname):
            if child in seen:
                cycle_start = seen.index(child)
                return path + [(fname, child)], seen[cycle_start:] + [child]
            if len(path) < 6:
                stack.append((child, path + [(fname, child)], seen + [child]))
            if best is None or len(path) + 1 > len(best):
                best = path + [(fname, child)]
    return best, None


def build_deep_query(types, root_name, depth):
    path, cycle = find_cycle_path(types, root_name, depth)
    if not path:
        return None
    names = [f for f, _ in path]
    if cycle:
        # repeat the cycle part until we reach the requested depth
        cyc_fields = names[-(len(cycle) - 1):] if len(cycle) > 1 else names[-1:]
        while len(names) < depth:
            names += cyc_fields
        names = names[:depth]
    q = "__typename"
    for n in reversed(names):
        q = f"{n} {{ {q} }}"
    return f"query SkDepth {{ {q} }}", len(names)


def evidence(c, r):
    return {"method": r["method"], "url": r["url"], "status": r["status"],
            "requestExcerpt": r.get("requestExcerpt", ""),
            "responseExcerpt": c.redact(f"HTTP {r['status']}\n{r['text'][:EXCERPT]}")}


def run(args):
    host = urllib.parse.urlparse(args.url).hostname
    if not host:
        sys.exit(f"error: invalid --url {args.url!r}")
    if not is_local(host) and not args.i_own_this_host:
        sys.exit(f"error: {host} is not localhost. Re-run with --i-own-this-host only after the user "
                 "explicitly confirms they own this system and authorize testing.")
    token = args.token or os.environ.get("SK_TOKEN_A")
    c = Client(args.url, token, args.auth_header, args.max_requests, args.timeout)
    cands, skipped, notes = [], [], []

    def cand(check, title, r, note):
        cands.append({"check_id": check, "title": title, "request": evidence(c, r), "note": note})

    base = c.send(body={"query": "{ __typename }"})
    if base["status"] == 0:
        raise RuntimeError(f"cannot reach {args.url}: {base.get('error')}")
    anonymous_ok = has_data(base, "__typename")
    if not anonymous_ok and token:
        c.use_token = True
        base = c.send(body={"query": "{ __typename }"})
    if not has_data(base, "__typename"):
        raise RuntimeError(f"endpoint did not answer a basic GraphQL query (HTTP {base['status']}): {base['text'][:200]}")
    identity = "anonymous" if not c.use_token else "token"
    notes.append(f"probing as {identity}")
    if anonymous_ok:
        cand("GQL-AUTHN-001", "Endpoint executes operations for anonymous callers", base,
             "Expected only if some operations are public; confirm each resolver requires auth where needed")

    # Introspection
    intro = c.send(body={"query": INTROSPECTION})
    types = None
    if has_data(intro, "__schema") and intro["json"]["data"]["__schema"]:
        types = intro["json"]["data"]["__schema"]["types"]
        cand("GQL-INTRO-001", f"Introspection enabled ({identity})", intro,
             f"schema returned with {len(types)} types")
    schema_query = None
    if types:
        qname = ((intro["json"]["data"]["__schema"].get("queryType") or {}).get("name")) or "Query"
        schema_query = qname

    # Field suggestions
    misspelled = "__typenme"
    if types:
        q = next((t for t in types if t["name"] == schema_query), None)
        fields = [f["name"] for f in (q or {}).get("fields") or [] if not required_args(f)]
        if fields:
            misspelled = fields[0][:-1] or fields[0] + "x"
    sug = c.send(body={"query": "{ %s }" % misspelled})
    if re.search(r"Did you mean", sug["text"], re.I):
        cand("GQL-INTRO-002", "Field suggestions enabled", sug, "error messages leak schema field names")

    # Array batching
    batch = c.send(body=[{"query": "{ __typename }"} for _ in range(10)])
    if isinstance(batch.get("json"), list) and len(batch["json"]) >= 10:
        cand("GQL-BATCH-001", "Array batching accepted (10 operations in one request)", batch,
             "confirm a cap exists and that rate limits count each operation")

    # Alias batching
    aliases = " ".join(f"a{i}: __typename" for i in range(args.aliases))
    al = c.send(body={"query": "{ %s }" % aliases})
    if has_data(al) and len(al["json"]["data"]) >= args.aliases:
        cand("GQL-BATCH-002", f"{args.aliases} aliases executed in one operation", al,
             "one request can run a field many times; matters for login/OTP/redeem mutations")

    # Depth
    if types and schema_query:
        built = build_deep_query(types, schema_query, args.depth)
        if built:
            q, depth = built
            deep = c.send(body={"query": q})
            if has_data(deep) and not (deep["json"].get("errors")):
                cand("GQL-DOS-001", f"Query of depth {depth} executed", deep, "no depth limit at or below this depth")
            elif re.search(r"depth|complex|cost", deep["text"], re.I):
                notes.append("depth/complexity limit appears to be enforced")
        else:
            skipped.append({"check_id": "GQL-DOS-001", "reason": "no nested object path without required arguments"})
    else:
        skipped.append({"check_id": "GQL-DOS-001", "reason": "introspection disabled; build a deep query from the schema by hand"})

    # Errors
    for bad in ("{ __typename ", "query ($x: Int!) { __typename }", "{ __type(name: 1) { name } }"):
        er = c.send(body={"query": bad})
        if STACK_RE.search(er["text"]):
            cand("GQL-ERR-001", "Internal error details in GraphQL error response", er,
                 "matched: " + STACK_RE.search(er["text"]).group(0)[:60])
            break

    # CSRF: GET execution and simple content types
    g = c.send(method="GET", query_string=urllib.parse.urlencode({"query": "{ __typename }"}))
    if has_data(g, "__typename"):
        notes.append("queries accepted over GET")
        gm = c.send(method="GET", query_string=urllib.parse.urlencode({"query": "mutation { __typename }"}))
        if has_data(gm, "__typename"):
            cand("GQL-CSRF-001", "Mutation executed over GET", gm, "cross-site links/images can trigger mutations if auth uses cookies")
    tp = c.send(raw=json.dumps({"query": "mutation { __typename }"}).encode(), content_type="text/plain")
    if has_data(tp, "__typename"):
        cand("GQL-CSRF-001", "Mutation accepted with Content-Type text/plain", tp,
             "a cross-site form/fetch can send this without a CORS preflight; matters if auth uses cookies")
    form = c.send(raw=urllib.parse.urlencode({"query": "mutation { __typename }"}).encode(),
                  content_type="application/x-www-form-urlencoded")
    if has_data(form, "__typename"):
        cand("GQL-CSRF-001", "Mutation accepted as form-encoded body", form, "cross-site HTML forms can trigger mutations")

    return {"tool": "securitykit-probe-graphql", "version": VERSION, "url": args.url,
            "requests_sent": c.sent, "candidates": cands, "skipped": skipped, "notes": notes}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Safe GraphQL probes (SecurityKit).")
    ap.add_argument("--url", required=True, help="full GraphQL endpoint URL, e.g. http://localhost:4000/graphql")
    ap.add_argument("--token", help="optional bearer token (or env SK_TOKEN_A); used only if anonymous access is refused")
    ap.add_argument("--auth-header", default="Authorization: Bearer {token}")
    ap.add_argument("--depth", type=int, default=12)
    ap.add_argument("--aliases", type=int, default=100)
    ap.add_argument("--i-own-this-host", action="store_true")
    ap.add_argument("--max-requests", type=int, default=40)
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    try:
        result = run(args)
    except RuntimeError as e:
        sys.exit(f"error: {e}")
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"{len(result['candidates'])} candidates -> {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
SecurityKit dynamic API probes (optional).

Sends a small number of safe requests to a running API and records candidate findings with the
exact request and response excerpt as evidence. The agent must still confirm each candidate.

Safety:
  * Refuses any host that is not localhost unless --i-own-this-host is passed.
  * Only GET / HEAD / OPTIONS, except the login rate-limit probe, which POSTs bogus
    credentials to --login-path (only if you pass it).
  * Never follows redirects; caps total requests (--max-requests).
  * Tokens are redacted from all output. Pass them via env vars SK_TOKEN_A, SK_TOKEN_B,
    SK_ADMIN_TOKEN to keep them out of shell history.

Standard library only.
"""

import argparse
import base64
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "0.1.0"
EVIL_ORIGIN = "https://securitykit-probe.invalid"
STACK_RE = re.compile(
    r"Traceback \(most recent call last\)|\bat [\w$.<>]+ \(.*?:\d+:\d+\)|at .*\.js:\d+:\d+|"
    r"java\.lang\.\w+Exception|org\.springframework\.|goroutine \d+ \[|"
    r"File \".*\.py\", line \d+|SQLSTATE|SequelizeDatabaseError|psycopg2\.|sqlite3\.|"
    r"MongoServerError|Werkzeug Debugger|<title>.*Error.*</title>",
    re.I,
)
MALFORMED = "1'\"<x>%00"
EXCERPT = 600


def is_local(host):
    host = (host or "").strip("[]").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Client:
    def __init__(self, base, auth_header, tokens, timeout, max_requests, delay):
        self.base = base.rstrip("/")
        self.auth_header = auth_header
        self.tokens = tokens
        self.timeout = timeout
        self.max_requests = max_requests
        self.delay = delay
        self.sent = 0
        self.opener = urllib.request.build_opener(NoRedirect)

    def redact(self, text):
        for t in self.tokens.values():
            if t and len(t) > 4:
                text = text.replace(t, t[:4] + "…")
        return text

    def request(self, method, path, as_=None, headers=None, body=None):
        if self.sent >= self.max_requests:
            raise RuntimeError("request budget exhausted")
        self.sent += 1
        url = self.base + path
        hdrs = {"User-Agent": f"SecurityKit-sk-api/{VERSION}", "Accept": "application/json, */*"}
        if as_ and self.tokens.get(as_):
            name, _, tmpl = self.auth_header.partition(":")
            hdrs[name.strip()] = tmpl.strip().replace("{token}", self.tokens[as_])
        hdrs.update(headers or {})
        data = json.dumps(body).encode() if body is not None else None
        if data is not None:
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            resp = self.opener.open(req, timeout=self.timeout)
            status, rh, raw = resp.status, dict(resp.headers), resp.read(64 * 1024)
        except urllib.error.HTTPError as e:
            status, rh, raw = e.code, dict(e.headers or {}), e.read(64 * 1024) if e.fp else b""
        except (urllib.error.URLError, OSError) as e:
            return {"method": method, "url": url, "as": as_ or "anonymous", "status": 0, "error": str(e),
                    "headers": {}, "body": ""}
        finally:
            if self.delay:
                time.sleep(self.delay)
        text = raw.decode("utf-8", errors="replace")
        req_line = f"{method} {path}" + "".join(f"\n{k}: {v}" for k, v in hdrs.items() if k.lower() != "user-agent")
        return {
            "method": method, "url": url, "as": as_ or "anonymous", "status": status,
            "headers": rh, "body": text, "requestExcerpt": self.redact(req_line),
        }


def evidence(client, r):
    head = "".join(f"{k}: {v}\n" for k, v in r["headers"].items()
                   if k.lower().startswith(("access-control", "content-type", "x-", "strict", "retry")))
    return {
        "method": r["method"], "url": r["url"], "as": r["as"], "status": r["status"],
        "requestExcerpt": r.get("requestExcerpt", ""),
        "responseExcerpt": client.redact(f"HTTP {r['status']}\n{head}\n{r['body'][:EXCERPT]}"),
    }


def fill(path, params):
    """Substitute {id} / :id style params. Returns None if any param has no value."""
    missing = []

    def sub(m):
        name = m.group(1) or m.group(2)
        if name in params:
            return urllib.parse.quote(params[name], safe="")
        if "*" in params:
            return urllib.parse.quote(params["*"], safe="")
        missing.append(name)
        return m.group(0)

    out = re.sub(r"\{(\w+)\}|(?<=/):(\w+)", sub, path)
    return None if missing else out


def is_jwt(tok):
    return bool(tok) and tok.count(".") == 2 and tok.startswith("eyJ")


def forge_none(tok):
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()
    payload = tok.split(".")[1]
    return f"{b64({'alg': 'none', 'typ': 'JWT'})}.{payload}."


def run(args):
    base = args.base_url
    host = urllib.parse.urlparse(base).hostname
    if not host:
        sys.exit(f"error: invalid --base-url {base!r}")
    if not is_local(host) and not args.i_own_this_host:
        sys.exit(
            f"error: {host} is not localhost. Dynamic tests only run against systems you own.\n"
            "Re-run with --i-own-this-host after the user has explicitly confirmed ownership."
        )
    tokens = {
        "userA": args.token_a or os.environ.get("SK_TOKEN_A"),
        "userB": args.token_b or os.environ.get("SK_TOKEN_B"),
        "admin": args.admin_token or os.environ.get("SK_ADMIN_TOKEN"),
    }
    params = dict(p.split("=", 1) for p in args.param)
    client = Client(base, args.auth_header, tokens, args.timeout, args.max_requests, args.delay)

    routes = []
    if args.routes:
        with open(args.routes, encoding="utf-8") as fh:
            routes = json.load(fh).get("routes", [])
    get_routes = []
    for r in routes:
        if r["method"] in ("GET", "ANY", "ALL"):
            p = r.get("path_normalized") or r["path"]
            if p not in [x[0] for x in get_routes]:
                get_routes.append((p, r))

    candidates, checks, skipped = [], [], []

    def cand(check_id, title, r, note):
        candidates.append({"check_id": check_id, "title": title, "request": evidence(client, r), "note": note})

    # API-CFG-001 / API-CFG-004 on the base path
    checks.append("API-CFG-001")
    r = client.request("GET", "/", headers={"Origin": EVIL_ORIGIN})
    if r["status"] == 0:
        raise RuntimeError(f"cannot reach {base}: {r.get('error')}. Is the app running?")
    h = {k.lower(): v for k, v in r["headers"].items()}
    acao, acac = h.get("access-control-allow-origin"), h.get("access-control-allow-credentials", "").lower()
    if acao in ("*", EVIL_ORIGIN) and acac == "true":
        cand("API-CFG-001", "CORS allows arbitrary origin with credentials", r,
             f"Access-Control-Allow-Origin: {acao} with Allow-Credentials: true")
    elif acao == EVIL_ORIGIN:
        cand("API-CFG-001", "CORS reflects arbitrary origin", r, "Origin is reflected without credentials; check if any route sets credentials")
    if r["status"]:
        checks.append("API-CFG-004")
        missing = [x for x in ("x-content-type-options", "strict-transport-security", "x-frame-options",
                               "content-security-policy") if x not in h]
        if missing and len(missing) >= 2:
            cand("API-CFG-004", "Missing security headers", r, "missing: " + ", ".join(missing))

    # API-ERR-001: malformed params and unknown route
    checks.append("API-ERR-001")
    probes = ["/securitykit-probe-404/" + urllib.parse.quote(MALFORMED, safe="")]
    for p, _ in get_routes:
        if re.search(r"\{\w+\}|:\w+", p):
            probes.append(re.sub(r"\{\w+\}|(?<=/):\w+", urllib.parse.quote(MALFORMED, safe=""), p))
    for p in probes[:15]:
        for as_ in ("anonymous", "userA") if tokens["userA"] else ("anonymous",):
            r = client.request("GET", p, as_=None if as_ == "anonymous" else as_)
            if STACK_RE.search(r["body"]):
                cand("API-ERR-001", "Stack trace or internal error in response", r,
                     "matched: " + STACK_RE.search(r["body"]).group(0)[:80])
                break

    # API-AUTHN-001: anonymous access
    checks.append("API-AUTHN-001")
    for p, route in get_routes:
        url = fill(p, params)
        if url is None:
            continue
        anon = client.request("GET", url)
        route["_anon"] = anon
        if 200 <= anon["status"] < 300 and route.get("auth") != "yes":
            cand("API-AUTHN-001", "Endpoint returns data without authentication", anon,
                 f"route marked auth={route.get('auth')}; confirm it should be public")

    # Authorization checks need tokens
    if tokens["userA"] and tokens["userB"]:
        checks += ["API-AUTHZ-001", "API-AUTHZ-002"]
        for p, route in get_routes:
            if not re.search(r"\{\w+\}|:\w+", p):
                continue
            url = fill(p, params)
            if url is None:
                skipped.append({"check_id": "API-AUTHZ-001", "route": p, "reason": "no --param value for path parameter"})
                continue
            ra = client.request("GET", url, as_="userA")
            rb = client.request("GET", url, as_="userB")
            if 200 <= ra["status"] < 300 and 200 <= rb["status"] < 300 and ra["body"] == rb["body"]:
                cand("API-AUTHZ-001", "User B can read the same object as user A", rb,
                     "both users got 2xx with identical bodies; confirm the object belongs to user A and is not public")
        for p, route in get_routes:
            if "admin" not in p.lower():
                continue
            url = fill(p, params)
            if url is None:
                continue
            ru = client.request("GET", url, as_="userA")
            if 200 <= ru["status"] < 300:
                cand("API-AUTHZ-002", "Normal user can access an admin route", ru, "user A got 2xx on an admin path")
    else:
        skipped.append({"check_id": "API-AUTHZ-001", "reason": "no test accounts (need --token-a and --token-b)"})
        skipped.append({"check_id": "API-AUTHZ-002", "reason": "no test accounts (need --token-a and --token-b)"})

    # API-AUTHN-003: alg=none
    if is_jwt(tokens["userA"]):
        checks.append("API-AUTHN-003")
        target = next((r for _, r in get_routes
                       if r.get("_anon") and r["_anon"]["status"] in (401, 403)), None)
        if target:
            url = fill(target.get("path_normalized") or target["path"], params)
            client.tokens["forged"] = forge_none(tokens["userA"])
            r = client.request("GET", url, as_="forged")
            if 200 <= r["status"] < 300:
                cand("API-AUTHN-003", "Server accepts JWT with alg=none", r, "unsigned token with user A's claims was accepted")
        else:
            skipped.append({"check_id": "API-AUTHN-003", "reason": "no route found that rejects anonymous requests"})
    else:
        skipped.append({"check_id": "API-AUTHN-003", "reason": "user A token is not a JWT"})

    # API-AUTHN-004: login rate limiting
    if args.login_path:
        checks.append("API-AUTHN-004")
        statuses, last = [], None
        for i in range(args.login_attempts):
            last = client.request("POST", args.login_path,
                                  body={args.login_user_field: f"securitykit-probe-{i}@invalid.test",
                                        args.login_password_field: "wrong-password-probe"})
            statuses.append(last["status"])
            if last["status"] == 429:
                break
        if 429 not in statuses and last and last["status"]:
            cand("API-AUTHN-004", "Login has no rate limiting", last,
                 f"{len(statuses)} failed logins, none returned 429 (statuses: {sorted(set(statuses))})")
    else:
        skipped.append({"check_id": "API-AUTHN-004", "reason": "no --login-path given"})

    return {
        "tool": "securitykit-dynamic-tests",
        "version": VERSION,
        "base_url": base,
        "requests_sent": client.sent,
        "checks_run": sorted(set(checks)),
        "candidates": candidates,
        "skipped": skipped,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Safe dynamic API probes (SecurityKit).")
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--routes", help="routes.json from discover_routes.py")
    ap.add_argument("--token-a", help="user A token (or env SK_TOKEN_A)")
    ap.add_argument("--token-b", help="user B token (or env SK_TOKEN_B)")
    ap.add_argument("--admin-token", help="admin token (or env SK_ADMIN_TOKEN)")
    ap.add_argument("--auth-header", default="Authorization: Bearer {token}")
    ap.add_argument("--param", action="append", default=[], metavar="NAME=VALUE",
                    help="value for a path parameter owned by user A, e.g. id=42 (use *=VALUE for all)")
    ap.add_argument("--login-path", help="POST endpoint for the rate-limit probe, e.g. /api/auth/login")
    ap.add_argument("--login-user-field", default="email")
    ap.add_argument("--login-password-field", default="password")
    ap.add_argument("--login-attempts", type=int, default=20)
    ap.add_argument("--i-own-this-host", action="store_true",
                    help="required for non-localhost targets; only after the user explicitly confirms ownership")
    ap.add_argument("--max-requests", type=int, default=300)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between requests")
    ap.add_argument("--out", help="write JSON here instead of stdout")
    args = ap.parse_args(argv)
    try:
        result = run(args)
    except RuntimeError as e:
        sys.exit(f"error: {e}")
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"{len(result['candidates'])} candidates, {result['requests_sent']} requests -> {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

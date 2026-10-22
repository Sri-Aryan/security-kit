#!/usr/bin/env python3
"""
SecurityKit OpenAPI contract audit (static, read-only, standard library only).

Finds OpenAPI 3.x / Swagger 2.0 specs (or fetches one from a local URL), lints the contract for security
concepts (default security, opt-outs, weak schemes, open request schemas, server-controlled fields,
sensitive response fields, missing limits, exposed hosts, secrets in examples) and, given the code's
route inventory, reports drift: undocumented routes, stale operations, method mismatches and
spec-vs-code auth mismatches.

Route inventory: --routes <json> (any tool producing {"routes": [{method, path, file, line, auth}]}),
or automatically from SecurityKit sk-api's discover_routes.py when installed alongside this skill.

Prints JSON: { specs, inventory, drift, candidates, warnings }. Candidates are leads for the agent.
YAML: uses PyYAML if installed, otherwise a built-in parser for block-style YAML (no anchors).
"""

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request

from sk_outputs import prepare_output

VERSION = "0.1.0"
METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
WRITE_METHODS = {"post", "put", "patch", "delete"}
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "target", "out", "__pycache__", ".venv", "venv",
             ".securitykit", ".claude", ".codex", "coverage", ".next", ".tox"}
SPEC_HINT = re.compile(r"""^\s*["']?(openapi|swagger)["']?\s*:""", re.M)

SENSITIVE_PROP = re.compile(
    r"^(password\w*|passwd|pass_?hash|\w*secret\w*|api_?key\w*|private_?key|\w*token\w*|ssn|social_?security\w*|"
    r"tax_?id|credit_?card\w*|card_?number|cvv|cvc|pin|iban|account_?number|otp\w*|mfa_?secret|salt)$",
    re.I,
)
SERVER_CONTROLLED = re.compile(
    r"^(id|_id|uuid|role|roles|is_?admin|admin|is_?staff|permissions?|owner(_?id)?|user_?id|tenant_?id|org_?id|"
    r"organization_?id|account_?id|created_?at|updated_?at|created_?by|balance|credits?|verified|is_?verified|"
    r"email_?verified|status|approved|is_?approved|plan|tier)$",
    re.I,
)
ERROR_LEAK_PROP = re.compile(r"^(stack|stack_?trace|trace|traceback|exception|sql|query|debug|internal\w*)$", re.I)
PAGINATION_PARAM = re.compile(r"^(limit|page_?size|per_?page|first|last|take|size|count|max|top|max_?results)$", re.I)
AUTH_ISH_PATH = re.compile(r"login|token|auth|oauth|session|signin|sign-in|refresh", re.I)
PRIVILEGED = re.compile(r"admin|role|permission|delete|remove|refund|impersonate|grant|revoke|ban|config|settings", re.I)
INTERNAL_HOST = re.compile(r"localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\.local\b|\.internal\b|\.corp\b|staging|stage\.|dev\.|"
                           r"\btest\.|\bqa\.|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+", re.I)
SECRET_IN_EXAMPLE = re.compile(
    r"\b(AKIA|ASIA)[0-9A-Z]{16}\b|\b(sk|rk)_live_[0-9a-zA-Z]{16,}|\bgh[pousr]_[A-Za-z0-9]{30,}|\bxox[abposr]-[A-Za-z0-9-]{10,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|\bwhsec_[A-Za-z0-9]{10,}"
)


# =========================================================================== minimal YAML

class YamlError(ValueError):
    pass


def _strip_comment(line):
    q = None
    for i, ch in enumerate(line):
        if q:
            if ch == q:
                q = None
        elif ch in "'\"":
            if i == 0 or line[i - 1] in " \t:[{,-":
                q = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
    return line.rstrip()


def _split_key(content):
    """('key', 'rest') if content is a mapping entry, else (None, None)."""
    if not content or content[0] in "[{":
        return None, None
    if content[0] in "'\"":
        q = content[0]
        end = content.find(q, 1)
        while q == "'" and end != -1 and content[end + 1:end + 2] == "'":
            end = content.find(q, end + 2)
        if end == -1:
            return None, None
        after = content[end + 1:].lstrip()
        if not after.startswith(":") or (len(after) > 1 and after[1] not in " \t"):
            return None, None
        return _scalar(content[:end + 1]), after[1:].strip()
    for i, ch in enumerate(content):
        if ch == ":" and (i + 1 == len(content) or content[i + 1] in " \t"):
            return content[:i].strip(), content[i + 1:].strip()
    return None, None


def _is_seq(content):
    return content == "-" or content.startswith("- ")


def _scalar(s):
    s = s.strip()
    if not s:
        return None
    if s[0] == '"' and s.endswith('"') and len(s) > 1:
        try:
            return json.loads(s)
        except ValueError:
            return s[1:-1]
    if s[0] == "'" and s.endswith("'") and len(s) > 1:
        return s[1:-1].replace("''", "'")
    if s in ("null", "Null", "NULL", "~"):
        return None
    if s in ("true", "True", "TRUE"):
        return True
    if s in ("false", "False", "FALSE"):
        return False
    if re.fullmatch(r"[-+]?\d+", s):
        return int(s)
    if re.fullmatch(r"[-+]?(\d+\.\d*|\.\d+|\d+)([eE][-+]?\d+)?", s):
        return float(s)
    return s


def _flow(s):
    pos = 0

    def ws():
        nonlocal pos
        while pos < len(s) and s[pos] in " \t\n":
            pos += 1

    def value(stop):
        nonlocal pos
        ws()
        if pos >= len(s):
            return None
        ch = s[pos]
        if ch == "[":
            pos += 1
            out = []
            while True:
                ws()
                if pos < len(s) and s[pos] == "]":
                    pos += 1
                    return out
                out.append(value(",]"))
                ws()
                if pos < len(s) and s[pos] == ",":
                    pos += 1
        if ch == "{":
            pos += 1
            out = {}
            while True:
                ws()
                if pos < len(s) and s[pos] == "}":
                    pos += 1
                    return out
                k = value(":,}")
                ws()
                v = None
                if pos < len(s) and s[pos] == ":":
                    pos += 1
                    v = value(",}")
                out[k] = v
                ws()
                if pos < len(s) and s[pos] == ",":
                    pos += 1
                if pos >= len(s):
                    raise YamlError("unterminated flow mapping")
        if ch in "'\"":
            end = pos + 1
            while end < len(s):
                if s[end] == "\\" and ch == '"':
                    end += 2
                    continue
                if s[end] == ch:
                    if ch == "'" and s[end + 1:end + 2] == "'":
                        end += 2
                        continue
                    break
                end += 1
            tok = s[pos:end + 1]
            pos = end + 1
            return _scalar(tok)
        start = pos
        while pos < len(s) and s[pos] not in stop:
            if s[pos] == ":" and ":" in stop and pos + 1 < len(s) and s[pos + 1] not in " ,}]":
                pos += 1
                continue
            pos += 1
        return _scalar(s[start:pos])

    return value("")


class MiniYaml:
    def __init__(self, text):
        self.raw = text.splitlines()
        self.toks = []
        for n, line in enumerate(self.raw):
            if line.strip() in ("---", "...") or line.lstrip().startswith("%"):
                continue
            c = _strip_comment(line)
            if c.strip():
                self.toks.append([len(c) - len(c.lstrip(" ")), c.strip(), n])

    def parse(self):
        if not self.toks:
            return None
        v, _ = self.node(0, self.toks[0][0])
        return v

    def node(self, i, ind):
        content = self.toks[i][1]
        if _is_seq(content):
            return self.seq(i, self.toks[i][0])
        if _split_key(content)[0] is not None:
            return self.map(i, self.toks[i][0])
        return self.value(i, content, ind - 1)

    def seq(self, i, ind):
        out = []
        while i < len(self.toks) and self.toks[i][0] == ind and _is_seq(self.toks[i][1]):
            content = self.toks[i][1]
            rest = content[1:].strip()
            col = ind + len(content) - len(rest)
            if not rest:
                if i + 1 < len(self.toks) and self.toks[i + 1][0] > ind:
                    v, i = self.node(i + 1, self.toks[i + 1][0])
                else:
                    v, i = None, i + 1
            elif _is_seq(rest) or (_split_key(rest)[0] is not None and rest[0] not in "[{"):
                self.toks[i] = [col, rest, self.toks[i][2]]
                v, i = self.node(i, col)
            else:
                v, i = self.value(i, rest, ind)
            out.append(v)
        return out, i

    def map(self, i, ind):
        out = {}
        while i < len(self.toks) and self.toks[i][0] == ind and not _is_seq(self.toks[i][1]):
            key, rest = _split_key(self.toks[i][1])
            if key is None:
                raise YamlError(f"line {self.toks[i][2] + 1}: expected 'key: value'")
            if not rest or re.fullmatch(r"&\S+", rest):
                nxt = self.toks[i + 1] if i + 1 < len(self.toks) else None
                if nxt and (nxt[0] > ind or (nxt[0] == ind and _is_seq(nxt[1]))):
                    v, i = self.node(i + 1, nxt[0])
                else:
                    v, i = None, i + 1
            else:
                v, i = self.value(i, rest, ind)
            if key != "<<":
                out[key] = v
        return out, i

    def value(self, i, rest, ind):
        rest = re.sub(r"^&\S+\s*", "", rest)
        if rest.startswith("*"):
            return None, i + 1  # aliases unsupported in the fallback parser
        if rest.startswith(("!!", "!")):
            rest = re.sub(r"^!\S*\s*", "", rest)
        if rest[:1] in ("|", ">"):
            j = i + 1
            while j < len(self.toks) and self.toks[j][0] > ind:
                j += 1
            first, last = self.toks[i][2] + 1, (self.toks[j - 1][2] if j > i + 1 else self.toks[i][2])
            block = self.raw[first:last + 1]
            pad = min((len(b) - len(b.lstrip()) for b in block if b.strip()), default=0)
            sep = "\n" if rest[0] == "|" else " "
            return sep.join(b[pad:] for b in block).strip("\n") + ("\n" if rest[0] == "|" else ""), j
        if rest[:1] in "[{":
            s, j = rest, i + 1
            while s.count("[") + s.count("{") > s.count("]") + s.count("}") and j < len(self.toks):
                s += " " + self.toks[j][1]
                j += 1
            return _flow(s), j
        s, j = rest, i + 1
        if s[:1] in "'\"" and not (len(s) > 1 and s.endswith(s[0])):
            while j < len(self.toks) and not s.endswith(rest[0]):
                s += " " + self.toks[j][1]
                j += 1
        else:
            while j < len(self.toks) and self.toks[j][0] > ind and _split_key(self.toks[j][1])[0] is None \
                    and not _is_seq(self.toks[j][1]):
                s += " " + self.toks[j][1]
                j += 1
        return _scalar(s), j


def load_text(text, name):
    if name.endswith(".json") or text.lstrip().startswith("{"):
        return json.loads(text)
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except ImportError:
        return MiniYaml(text).parse()


# =========================================================================== spec helpers

def locate(text, keys):
    """Line of the last key in `keys`, found in sequence (works for YAML and pretty JSON)."""
    pos, line = 0, 1
    for k in keys:
        rx = re.compile(r"""^[ \t]*-?[ \t]*["']?%s["']?[ \t]*:""" % re.escape(str(k)), re.M)
        m = rx.search(text, pos)
        if not m:
            return line
        pos = m.end()
        line = text.count("\n", 0, m.start()) + 1
    return line


def deref(node, spec, seen=None):
    seen = seen or set()
    while isinstance(node, dict) and isinstance(node.get("$ref"), str) and node["$ref"].startswith("#/"):
        ref = node["$ref"]
        if ref in seen:
            return {}
        seen = seen | {ref}
        cur = spec
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            cur = cur.get(part) if isinstance(cur, dict) else None
        node = cur if cur is not None else {}
    return node


def ref_name(node):
    if isinstance(node, dict) and isinstance(node.get("$ref"), str):
        return node["$ref"].rsplit("/", 1)[-1]
    return None


def walk_props(schema, spec, path=(), depth=0, seen=None):
    """Yield (prop_path, prop_schema, owner_ref) for properties, following $ref/allOf/items."""
    seen = seen or set()
    if depth > 5 or not isinstance(schema, dict):
        return
    name = ref_name(schema)
    if name:
        if name in seen:
            return
        seen = seen | {name}
    s = deref(schema, spec)
    if not isinstance(s, dict):
        return
    for key in ("allOf", "oneOf", "anyOf"):
        for sub in s.get(key) or []:
            yield from walk_props(sub, spec, path, depth + 1, seen)
    if isinstance(s.get("items"), dict):
        yield from walk_props(s["items"], spec, path + ("[]",), depth + 1, seen)
    for pname, pschema in (s.get("properties") or {}).items():
        yield path + (pname,), deref(pschema, spec), name
        yield from walk_props(pschema, spec, path + (pname,), depth + 1, seen)


def norm_path(p):
    p = re.sub(r"\{[^}]+\}", "{}", p)
    p = re.sub(r"(?<=/):[A-Za-z_]\w*\??", "{}", p)
    p = re.sub(r"<[^>]+>", "{}", p)
    p = re.sub(r"//+", "/", p)
    return p.rstrip("/") or "/"


def is_local(host):
    host = (host or "").strip("[]").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# =========================================================================== audit

class Spec:
    def __init__(self, name, text, data):
        self.name, self.text, self.data = name, text, data
        self.v2 = "swagger" in data
        self.version = str(data.get("openapi") or data.get("swagger"))

    def schemes(self):
        if self.v2:
            return self.data.get("securityDefinitions") or {}
        return ((self.data.get("components") or {}).get("securitySchemes")) or {}

    def base_paths(self):
        out = {""}
        if self.v2:
            out.add((self.data.get("basePath") or "").rstrip("/"))
        for s in self.data.get("servers") or []:
            url = (s or {}).get("url") or ""
            for var, spec in ((s or {}).get("variables") or {}).items():
                url = url.replace("{%s}" % var, str((spec or {}).get("default", "")))
            out.add(urllib.parse.urlparse(url).path.rstrip("/"))
        return out

    def operations(self):
        for path, item in (self.data.get("paths") or {}).items():
            item = deref(item, self.data) or {}
            if not isinstance(item, dict):
                continue
            shared = item.get("parameters") or []
            for m in METHODS:
                op = item.get(m)
                if isinstance(op, dict):
                    params = [deref(p, self.data) for p in shared + (op.get("parameters") or [])]
                    yield path, m, op, params

    def line(self, *keys):
        return locate(self.text, keys)

    def line_of_text(self, needle):
        i = self.text.find(needle)
        return self.text.count("\n", 0, i) + 1 if i >= 0 else 1


def audit(specs, routes, warnings):
    cands, inventory = [], []

    def cand(check, title, file, line, confidence, note=""):
        cands.append({"check_id": check, "title": title, "file": file, "line": line,
                      "snippet": snippet(file, line), "confidence": confidence, "note": note})

    texts = {s.name: s.text.splitlines() for s in specs}

    def snippet(file, line):
        ls = texts.get(file)
        if ls and line and 0 < line <= len(ls):
            return ls[line - 1].strip()[:200]
        return ""

    spec_ops = {}  # (METHOD, norm path) -> info
    any_429 = False
    for s in specs:
        d = s.data
        schemes = s.schemes()
        global_sec = d.get("security")
        cand_src = s.name

        # ---------- schemes
        if not schemes:
            cand("OAS-AUTH-001", "No security schemes defined", cand_src, s.line("paths"), "HIGH",
                 "if the API requires auth, the contract does not say how")
        for sname, sch in schemes.items():
            sch = deref(sch, d) or {}
            t = (sch.get("type") or "").lower()
            ln = s.line("securityDefinitions" if s.v2 else "securitySchemes", sname)
            if (t == "http" and (sch.get("scheme") or "").lower() == "basic") or t == "basic":
                cand("OAS-AUTH-004", f"HTTP Basic auth scheme '{sname}'", cand_src, ln, "MEDIUM", "password sent on every request")
            if t == "apikey" and (sch.get("in") or "").lower() == "query":
                cand("OAS-AUTH-004", f"API key in query string ('{sname}')", cand_src, ln, "HIGH", "keys leak into logs, history and proxies")
            flows = set((sch.get("flows") or {}).keys()) | ({sch.get("flow")} if sch.get("flow") else set())
            for weak in flows & {"implicit", "password"}:
                cand("OAS-AUTH-004", f"OAuth2 {weak} flow in '{sname}'", cand_src, ln, "MEDIUM", "deprecated by OAuth 2.1 best practice")

        # ---------- servers
        servers = [(x or {}).get("url", "") for x in d.get("servers") or []]
        if s.v2:
            host = d.get("host") or ""
            servers += [f"{sch}://{host}" for sch in (d.get("schemes") or ["https"])] if host else []
        for url in servers:
            if url.startswith("http://") and not is_local(urllib.parse.urlparse(url).hostname):
                cand("OAS-EXPO-001", f"Server over plain HTTP: {url}", cand_src, s.line_of_text(url.split("://", 1)[-1]), "MEDIUM")
            if INTERNAL_HOST.search(url):
                cand("OAS-EXPO-001", f"Internal / non-production host in spec: {url}", cand_src,
                     s.line_of_text(url.split("://", 1)[-1]), "LOW",
                     "fine for an internal spec; remove from a public one")

        # ---------- examples
        def scan_examples(node, keys):
            if isinstance(node, dict):
                for k, v in node.items():
                    if k in ("example", "examples", "default", "x-example") and SECRET_IN_EXAMPLE.search(json.dumps(v)):
                        cand("OAS-EXPO-002", "Secret-looking value in spec example/default", cand_src,
                             s.line(*(keys + [k])), "MEDIUM", "use obviously fake values; rotate it if it is real")
                    else:
                        scan_examples(v, keys + [k])
            elif isinstance(node, list):
                for v in node:
                    scan_examples(v, keys)
        scan_examples(d, [])

        # ---------- operations
        unsecured_default, missing_4xx, loose_strings = [], [], []
        flagged_schema = set()
        for path, m, op, params in s.operations():
            ln = s.line("paths", path, m)
            sec = op["security"] if "security" in op else global_sec
            public = sec is None or sec == []
            optional = isinstance(sec, list) and any(r == {} for r in sec)
            responses = {str(k): deref(v, d) for k, v in (op.get("responses") or {}).items()}
            any_429 = any_429 or "429" in responses
            for base in s.base_paths():
                spec_ops[(m.upper(), norm_path(base + path))] = {
                    "spec": cand_src, "line": ln, "path": path, "method": m, "secured": not public,
                    "deprecated": bool(op.get("deprecated")), "base": base}

            if "security" in op and (op["security"] == [] or optional):
                cand("OAS-AUTH-002", f"{m.upper()} {path} is {'public' if op['security'] == [] else 'optionally authenticated'}",
                     cand_src, ln,
                     "LOW" if AUTH_ISH_PATH.search(path) or re.search(r"register|signup|sign-up", path, re.I)
                     else ("HIGH" if m in WRITE_METHODS else "MEDIUM"),
                     "confirm this is intentional")
            elif sec is None and schemes:
                unsecured_default.append((m, path, ln))
            if not public and not ({"401", "403"} & set(responses)) and "default" not in responses:
                missing_4xx.append((m, path, ln))
            if not public and PRIVILEGED.search(path + " " + str(op.get("operationId", ""))) and isinstance(sec, list):
                oauth = any((deref(schemes.get(n), d) or {}).get("type") == "oauth2" for r in sec if isinstance(r, dict) for n in r)
                if oauth and all(not scopes for r in sec if isinstance(r, dict) for scopes in r.values()):
                    cand("OAS-AUTH-005", f"Privileged {m.upper()} {path} requires no specific scope", cand_src, ln, "LOW")
            if op.get("deprecated"):
                cand("OAS-DRIFT-004", f"Deprecated operation {m.upper()} {path}", cand_src, ln, "LOW",
                     "confirm whether it is still served (see drift results)")

            # parameters
            for p in params:
                if not isinstance(p, dict):
                    continue
                schema = deref(p.get("schema") or p, d) or {}
                if p.get("in") == "query" and PAGINATION_PARAM.match(str(p.get("name", ""))) and "maximum" not in schema:
                    cand("OAS-LIMIT-001", f"Pagination parameter '{p.get('name')}' on {m.upper()} {path} has no maximum",
                         cand_src, ln, "MEDIUM")

            # request bodies
            bodies = []
            if s.v2:
                bodies += [("application/json", p.get("schema")) for p in params if isinstance(p, dict) and p.get("in") == "body"]
                if any(isinstance(p, dict) and p.get("type") == "file" for p in params):
                    cand("OAS-LIMIT-002", f"File upload on {m.upper()} {path}: confirm size and type limits", cand_src, ln, "LOW")
            else:
                rb = deref(op.get("requestBody"), d) or {}
                for ctype, media in (rb.get("content") or {}).items():
                    bodies.append((ctype, (media or {}).get("schema")))
            for ctype, schema in bodies:
                if schema is None:
                    continue
                rs = deref(schema, d) or {}
                name = ref_name(schema) or ref_name(rs.get("items") if isinstance(rs, dict) else None)
                sline = s.line("components" if not s.v2 else "definitions", "schemas", name) if name and not s.v2 \
                    else (s.line("definitions", name) if name else ln)
                if "multipart" in ctype or "octet-stream" in ctype or any(
                        (ps or {}).get("format") == "binary" for _, ps, _ in walk_props(schema, d)):
                    cand("OAS-LIMIT-002", f"Upload on {m.upper()} {path}: no size limit declared", cand_src, ln, "MEDIUM",
                         "declare maxLength / document limits, and enforce them server-side")
                if m in WRITE_METHODS and isinstance(rs, dict) and (rs.get("type") == "object" or "properties" in rs) \
                        and rs.get("additionalProperties") is not False:
                    key = name or f"{m}{path}"
                    if key not in flagged_schema:
                        flagged_schema.add(key)
                        cand("OAS-DATA-001", f"Request schema {name or '(inline)'} accepts unknown fields ({m.upper()} {path})",
                             cand_src, sline, "MEDIUM", "set additionalProperties: false and enforce validation")
                if m in WRITE_METHODS:
                    for prop_path, ps, owner in walk_props(schema, d):
                        leaf = prop_path[-1]
                        if SERVER_CONTROLLED.match(leaf) and not (ps or {}).get("readOnly"):
                            k = (owner or path, ".".join(prop_path))
                            if k not in flagged_schema:
                                flagged_schema.add(k)
                                cand("OAS-DATA-002", f"Server-controlled field '{'.'.join(prop_path)}' writable in {m.upper()} {path}",
                                     cand_src, s.line("schemas", owner, leaf) if owner and not s.v2 else ln, "MEDIUM",
                                     "mark readOnly or remove from the request schema; confirm the server ignores it")
                        if (ps or {}).get("type") == "string" and not any(x in (ps or {}) for x in ("maxLength", "enum", "format", "pattern", "const")):
                            loose_strings.append(f"{m.upper()} {path}: {'.'.join(prop_path)}")
                        if (ps or {}).get("type") == "array" and "maxItems" not in (ps or {}):
                            cand("OAS-LIMIT-001", f"Array '{'.'.join(prop_path)}' in {m.upper()} {path} has no maxItems",
                                 cand_src, ln, "LOW")

            # responses
            for code, resp in responses.items():
                media = (resp or {}).get("content") or ({"application/json": {"schema": resp.get("schema")}} if s.v2 and resp else {})
                for _, mt in media.items():
                    schema = (mt or {}).get("schema")
                    if not schema:
                        continue
                    for prop_path, ps, owner in walk_props(schema, d):
                        leaf = prop_path[-1]
                        if code.startswith("2") and SENSITIVE_PROP.match(leaf) and not (ps or {}).get("writeOnly"):
                            if re.search(r"token", leaf, re.I) and AUTH_ISH_PATH.search(path):
                                continue
                            k = ("resp", owner or path, ".".join(prop_path))
                            if k not in flagged_schema:
                                flagged_schema.add(k)
                                cand("OAS-DATA-003", f"Response of {m.upper()} {path} includes '{'.'.join(prop_path)}'",
                                     cand_src, s.line("schemas", owner, leaf) if owner and not s.v2 else ln, "HIGH")
                        if (code.startswith(("4", "5")) or code == "default") and ERROR_LEAK_PROP.match(leaf):
                            k = ("err", owner or path, leaf)
                            if k not in flagged_schema:
                                flagged_schema.add(k)
                                cand("OAS-DATA-005", f"Error response {code} of {m.upper()} {path} has '{leaf}'",
                                     cand_src, s.line("schemas", owner, leaf) if owner and not s.v2 else ln, "MEDIUM")
            inventory_key = (m.upper(), path)
            inventory.append({"kind": "operation", "name": f"{m.upper()} {path}", "method": m.upper(), "path": path,
                              "file": cand_src, "line": ln, "in_spec": True, "spec_security": "none" if public else ("optional" if optional else "required")})

        if unsecured_default:
            m, path, ln = unsecured_default[0]
            cand("OAS-AUTH-001", f"No global security requirement: {len(unsecured_default)} operation(s) have no security",
                 cand_src, ln, "HIGH", "e.g. " + ", ".join(f"{x[0].upper()} {x[1]}" for x in unsecured_default[:6]))
        if missing_4xx:
            m, path, ln = missing_4xx[0]
            cand("OAS-AUTH-006", f"{len(missing_4xx)} secured operation(s) document no 401/403", cand_src, ln, "LOW")
        if loose_strings:
            cand("OAS-DATA-004", f"{len(loose_strings)} request string field(s) without maxLength/pattern/format/enum",
                 cand_src, s.line("paths"), "LOW", "e.g. " + "; ".join(loose_strings[:6]))
    if specs and not any_429:
        cand("OAS-LIMIT-003", "No operation documents a 429 response", specs[0].name, specs[0].line("paths"), "LOW")

    # ---------- drift
    drift = {"compared": False}
    if routes is not None:
        drift = {"compared": True, "undocumented": [], "stale": [], "method_mismatch": [], "auth_mismatch": []}
        code = {}
        for r in routes:
            code.setdefault((r["method"].upper(), norm_path(r.get("path_normalized") or r["path"])), r)
        spec_paths = {p for (_, p) in spec_ops}
        code_paths = {p for (_, p) in code}
        matched_spec = set()
        for (meth, p), r in sorted(code.items()):
            if meth in ("ANY", "ALL"):
                hits = [k for k in spec_ops if k[1] == p]
            else:
                hits = [k for k in ((meth, p),) if k in spec_ops]
            if hits:
                for h in hits:
                    matched_spec.add((spec_ops[h]["method"], spec_ops[h]["path"]))
                    info = spec_ops[h]
                    if info["secured"] and r.get("auth") == "no":
                        drift["auth_mismatch"].append(f"{meth} {r['path']}")
                        cands.append({"check_id": "OAS-AUTH-003", "title": f"Spec says {h[0]} {info['path']} is secured; code shows no auth",
                                      "file": r["file"], "line": r["line"], "snippet": "", "confidence": "HIGH",
                                      "note": f"spec: {info['spec']}:{info['line']}; signals: {', '.join(r.get('auth_signals') or []) or 'none'}"})
                    if info["deprecated"]:
                        cands.append({"check_id": "OAS-DRIFT-004", "title": f"Deprecated {h[0]} {info['path']} is still served",
                                      "file": r["file"], "line": r["line"], "snippet": "", "confidence": "MEDIUM", "note": ""})
                continue
            check = "OAS-DRIFT-003" if p in spec_paths else "OAS-DRIFT-001"
            (drift["method_mismatch"] if check == "OAS-DRIFT-003" else drift["undocumented"]).append(f"{meth} {r['path']}")
            cands.append({"check_id": check,
                          "title": f"{meth} {r['path']} is in code but {'that method is not' if check == 'OAS-DRIFT-003' else 'not'} in the spec",
                          "file": r["file"], "line": r["line"], "snippet": "", "confidence": "MEDIUM" if check == "OAS-DRIFT-001" else "LOW",
                          "note": f"code auth: {r.get('auth')}"})
            inventory.append({"kind": "route", "name": f"{meth} {r['path']}", "method": meth, "path": r["path"],
                              "file": r["file"], "line": r["line"], "in_spec": False, "in_code": True, "code_auth": r.get("auth")})
        seen_stale = set()
        for (meth, p), info in spec_ops.items():
            key = (info["method"], info["path"])
            if key in matched_spec or key in seen_stale:
                continue
            # an op is stale only if no base-path variant matched
            if any((info["method"].upper(), norm_path(b + info["path"])) in code or ("ANY", norm_path(b + info["path"])) in code
                   for b in [""] + [x["base"] for x in spec_ops.values()]):
                continue
            seen_stale.add(key)
            check = "OAS-DRIFT-003" if any(norm_path(b + info["path"]) in code_paths for b in {x["base"] for x in spec_ops.values()} | {""}) else "OAS-DRIFT-002"
            (drift["method_mismatch"] if check == "OAS-DRIFT-003" else drift["stale"]).append(f"{meth} {info['path']}")
            cands.append({"check_id": check, "title": f"{meth} {info['path']} is in the spec but not found in code",
                          "file": info["spec"], "line": info["line"], "snippet": snippet(info["spec"], info["line"]),
                          "confidence": "MEDIUM" if check == "OAS-DRIFT-002" else "LOW",
                          "note": "may be served by another service or registered in a way route discovery misses"})
        for inv in inventory:
            if inv["kind"] == "operation":
                k = (inv["method"], norm_path(inv["path"]))
                hit = next((code[(inv["method"], norm_path(b + inv["path"]))] for b in {x["base"] for x in spec_ops.values()} | {""}
                            if (inv["method"], norm_path(b + inv["path"])) in code), None)
                inv["in_code"] = bool(hit)
                inv["code_auth"] = hit.get("auth") if hit else None
        versions = {m.group(1) for r in routes for m in [re.match(r"^/(?:api/)?(v\d+)/", r["path"])] if m}
        spec_versions = {m.group(1) for (_, p) in spec_ops for m in [re.match(r"^/(?:api/)?(v\d+)/", p)] if m}
        for v in sorted(versions - spec_versions):
            r = next(r for r in routes if re.match(r"^/(?:api/)?%s/" % v, r["path"]))
            cands.append({"check_id": "OAS-DRIFT-005", "title": f"API version {v} is served in code but absent from the spec",
                          "file": r["file"], "line": r["line"], "snippet": "", "confidence": "MEDIUM",
                          "note": "old versions often lack newer security fixes"})
    return cands, inventory, drift


# =========================================================================== IO

def find_specs(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        for f in sorted(filenames):
            if not f.lower().endswith((".yaml", ".yml", ".json")) or f.endswith(("package.json", "package-lock.json", "tsconfig.json")):
                continue
            full = os.path.join(dirpath, f)
            try:
                if os.path.getsize(full) > 5_000_000:
                    continue
                with open(full, encoding="utf-8", errors="replace") as fh:
                    head = fh.read(4096)
            except OSError:
                continue
            if SPEC_HINT.search(head):
                out.append(full)
    return out


def load_routes(args, warnings):
    if args.routes:
        with open(args.routes, encoding="utf-8") as fh:
            return json.load(fh).get("routes", [])
    here = os.path.dirname(os.path.abspath(__file__))
    discover = os.path.normpath(os.path.join(here, "..", "..", "sk-api", "scripts", "discover_routes.py"))
    if not os.path.exists(discover):
        warnings.append("no route inventory: install sk-api or pass --routes <json>; drift checks skipped")
        return None
    r = subprocess.run([sys.executable, discover, "--root", args.root], capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        warnings.append(f"route discovery failed: {r.stderr[-300:]}")
        return None
    data = json.loads(r.stdout)
    warnings += [f"route discovery: {w}" for w in data.get("warnings", [])]
    return data.get("routes", [])


def main(argv=None):
    ap = argparse.ArgumentParser(description="Audit OpenAPI/Swagger specs and spec-vs-code drift (SecurityKit).")
    ap.add_argument("--root", default=".")
    ap.add_argument("--spec", action="append", default=[], help="spec file (repeatable); default: auto-detect")
    ap.add_argument("--spec-url", help="fetch the spec from a running app (localhost only unless --i-own-this-host)")
    ap.add_argument("--i-own-this-host", action="store_true")
    ap.add_argument("--routes", help="route inventory JSON; default: sk-api discover_routes.py if installed")
    ap.add_argument("--no-drift", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)
    warnings, specs = [], []

    sources = [os.path.abspath(p) for p in args.spec] or find_specs(root)
    for path in sources:
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        try:
            with open(path, encoding="utf-8-sig") as fh:
                text = fh.read()
            data = load_text(text, path)
        except (OSError, ValueError) as e:
            warnings.append(f"could not parse {rel}: {e}")
            continue
        if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
            specs.append(Spec(rel, text, data))
    if args.spec_url:
        host = urllib.parse.urlparse(args.spec_url).hostname
        if not is_local(host) and not args.i_own_this_host:
            sys.exit(f"error: {host} is not localhost; pass --i-own-this-host only after the user confirms ownership")
        try:
            with urllib.request.urlopen(args.spec_url, timeout=15) as r:
                text = r.read(5_000_000).decode("utf-8", "replace")
            specs.append(Spec(args.spec_url, text, load_text(text, args.spec_url)))
        except (OSError, ValueError) as e:
            warnings.append(f"could not fetch {args.spec_url}: {e}")

    routes = None if args.no_drift else load_routes(args, warnings)
    if not specs:
        warnings.append("no OpenAPI/Swagger spec found (try --spec-url against the running app)")
    cands, inventory, drift = audit(specs, routes, warnings) if specs else ([{
        "check_id": "OAS-INV-001", "title": "No machine-readable API spec found", "file": None, "line": None,
        "snippet": "", "confidence": "MEDIUM", "note": f"{len(routes or [])} routes in code have no contract"}], [], {"compared": False})

    result = {
        "tool": "securitykit-openapi-audit", "version": VERSION, "root": ".",
        "specs": [{"file": s.name, "version": s.version, "title": (s.data.get("info") or {}).get("title"),
                   "operations": sum(1 for _ in s.operations())} for s in specs],
        "code_routes": len(routes) if routes is not None else None,
        "drift": drift, "inventory": inventory, "candidates": cands, "warnings": warnings,
    }
    text = json.dumps(result, indent=2, default=str)
    if args.out:
        prepare_output(args.out)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"{len(specs)} spec(s), {len(cands)} candidates -> {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

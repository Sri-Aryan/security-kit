#!/usr/bin/env python3
"""
SecurityKit endpoint inventory.

Finds HTTP endpoints in a project and prints JSON:
  { "root", "frameworks", "routes": [ {method, path, path_normalized, file, line, handler,
    framework, auth, auth_signals} ], "warnings" }

Supported: Express, Fastify, NestJS (JS/TS); FastAPI, Flask, Django/DRF (Python);
Spring Boot (Java/Kotlin); Go net/http, Gin, Echo, chi, gorilla/mux.

This is a heuristic, read-only scanner. "auth" is a lead for the agent, not a verdict:
  yes      an auth-looking middleware/decorator/dependency applies (see auth_signals)
  no       nothing auth-looking was found
  unknown  auth is configured globally in a way we cannot map to routes (e.g. Spring Security)

Standard library only. Never executes project code.
"""

import argparse
import ast
import bisect
import json
import os
import re
import sys

VERSION = "0.1.0"

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "target", "out", ".next", ".nuxt",
    "__pycache__", ".venv", "venv", "env", ".tox", ".mypy_cache", ".pytest_cache",
    ".securitykit", ".claude", ".codex", "coverage", ".idea", ".vscode", "bin", "obj",
}
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "testdata"}
TEST_FILE_RE = re.compile(r"(\.(test|spec)\.[cm]?[jt]sx?$)|(^test_.*\.py$)|(_test\.(py|go)$)|(Tests?\.(java|kt)$)")
JS_EXT = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"}
MAX_FILE_BYTES = 1_500_000

AUTH_RE = re.compile(
    r"auth|jwt|login_?required|passport|guard|protect|require_?(user|admin|role|login|session)|"
    r"is_?(admin|logged|staff)|permission|roles?_?(required|allowed)|secured|preauthorize|"
    r"verify_?(token|user|session|key)|ensure_?logged|current_?user|api_?key|bearer|session_required",
    re.I,
)
PUBLIC_RE = re.compile(r"public|allow_?any|permit_?all|no_?auth|skip_?auth|optional_?auth|anonymous", re.I)
HTTP_METHODS = ["get", "post", "put", "patch", "delete", "options", "head"]


# --------------------------------------------------------------------------- helpers

def classify(names):
    """Return (signals, public) from a list of middleware/decorator names."""
    signals, public = [], []
    for n in names:
        if not n:
            continue
        if PUBLIC_RE.search(n):
            public.append(n)
        elif AUTH_RE.search(n):
            signals.append(n)
    return signals, public


def join_path(a, b):
    a = a or ""
    b = b or ""
    if not a:
        return b if b.startswith("/") or not b else "/" + b
    if b in ("", "/"):
        return a if a.startswith("/") else "/" + a
    out = a.rstrip("/") + "/" + b.lstrip("/")
    return out if out.startswith("/") else "/" + out


def normalize_path(p):
    """Express :id, Flask <int:id>, Spring {id:\\d+}, Django <int:pk> -> {id}."""
    p = re.sub(r"<(?:[^:>]+:)?([^>]+)>", r"{\1}", p)
    p = re.sub(r"(?<=/):([A-Za-z_]\w*)\??", r"{\1}", p)
    p = re.sub(r"\{([A-Za-z_]\w*):[^}]*\}", r"{\1}", p)
    p = re.sub(r"\(\?P<(\w+)>[^)]*\)", r"{\1}", p)
    p = p.replace("^", "").replace("$", "")
    p = re.sub(r"//+", "/", p)
    return p or "/"


class LineIndex:
    def __init__(self, text):
        self.starts = [0] + [m.end() for m in re.finditer(r"\n", text)]

    def line(self, offset):
        return bisect.bisect_right(self.starts, offset)


def blank_comments(src):
    """Replace // and /* */ comments with spaces (keeps offsets). Aware of '', "", `` strings."""
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        ch = src[i]
        if ch in "'\"`":
            q = ch
            i += 1
            while i < n and src[i] != q:
                if src[i] == "\\":
                    i += 1
                elif src[i] == "\n" and q != "`":
                    break
                i += 1
            i += 1
        elif ch == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
        elif ch == "/" and i + 1 < n and src[i + 1] == "*":
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                if src[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n:
                out[i] = out[i + 1] = " "
            i += 2
        else:
            i += 1
    return "".join(out)


def find_close(src, open_idx):
    """Index of the bracket closing src[open_idx], string-aware. -1 if unbalanced."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = []
    i, n = open_idx, len(src)
    while i < n:
        ch = src[i]
        if ch in "'\"`":
            q = ch
            i += 1
            while i < n and src[i] != q:
                if src[i] == "\\":
                    i += 1
                i += 1
        elif ch in pairs:
            stack.append(pairs[ch])
        elif ch in ")]}":
            if not stack or stack.pop() != ch:
                return -1
            if not stack:
                return i
        i += 1
    return -1


def split_args(s):
    """Split on top-level commas, string- and bracket-aware."""
    parts, depth, cur, i, n = [], 0, [], 0, len(s)
    while i < n:
        ch = s[i]
        if ch in "'\"`":
            q = ch
            j = i + 1
            while j < n and s[j] != q:
                if s[j] == "\\":
                    j += 1
                j += 1
            cur.append(s[i:j + 1])
            i = j + 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return parts


def is_inline_fn(arg):
    return bool(re.match(r"^(async\s+)?(function\b|\(|[A-Za-z_$][\w$]*\s*=>)", arg)) or "=>" in arg.split("\n")[0]


def arg_names(arg):
    """Names referenced by a middleware argument: `auth`, `passport.authenticate('jwt')`, `[a, b]`, `{preHandler: [a]}`."""
    arg = arg.strip()
    if not arg or is_inline_fn(arg):
        return []
    if arg[0] in "[{":
        return re.findall(r"[A-Za-z_$][\w$.]*", arg)
    m = re.match(r"(?:new\s+)?([A-Za-z_$][\w$.]*)", arg)
    return [m.group(1)] if m else []


def handler_name(arg):
    arg = arg.strip()
    m = re.match(r"(?:async\s+)?function\s+([A-Za-z_$][\w$]*)", arg)
    if m:
        return m.group(1)
    if is_inline_fn(arg):
        return "<inline>"
    m = re.match(r"([A-Za-z_$][\w$.]*)", arg)
    return m.group(1) if m else None


def str_literal(arg):
    m = re.match(r"""^\s*(['"`])((?:(?!\1).)*)\1\s*$""", arg, re.S)
    return m.group(2) if m else None


# --------------------------------------------------------------------------- project

class Project:
    def __init__(self, root, include_tests=False):
        self.root = os.path.abspath(root)
        self.include_tests = include_tests
        self.files = []
        self.routes = []
        self.frameworks = set()
        self.warnings = []
        self._text = {}
        self._walk()

    def _walk(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(
                d for d in dirnames
                if d not in SKIP_DIRS and not d.startswith(".")
                and (self.include_tests or d not in TEST_DIRS)
            )
            for f in sorted(filenames):
                if not self.include_tests and TEST_FILE_RE.search(f):
                    continue
                full = os.path.join(dirpath, f)
                try:
                    if os.path.getsize(full) > MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue
                self.files.append(full)

    def rel(self, path):
        return os.path.relpath(path, self.root).replace(os.sep, "/")

    def text(self, path):
        if path not in self._text:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    self._text[path] = fh.read()
            except OSError as exc:
                self.warnings.append(f"cannot read {self.rel(path)}: {exc}")
                self._text[path] = ""
        return self._text[path]

    def by_ext(self, exts):
        return [f for f in self.files if os.path.splitext(f)[1] in exts]

    def add(self, framework, method, path, file, line, handler, signals, public=(), default=None, notes=()):
        """notes: context shown in auth_signals that does not by itself make auth "yes"."""
        signals = list(dict.fromkeys(s for s in signals if s))
        if public and not signals:
            auth = "no"
            signals = [f"public: {p}" for p in public]
        elif signals:
            auth = "yes"
        else:
            auth = default or "no"
            signals = list(notes)
        self.frameworks.add(framework)
        self.routes.append({
            "method": method.upper(),
            "path": path or "/",
            "path_normalized": normalize_path(path or "/"),
            "file": self.rel(file),
            "line": line,
            "handler": handler,
            "framework": framework,
            "auth": auth,
            "auth_signals": signals,
        })


# --------------------------------------------------------------------------- JS / TS

JS_IMPORT_RE = re.compile(
    r"""(?:(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\))|"""
    r"""(?:import\s+([A-Za-z_$][\w$]*)\s+from\s+['"]([^'"]+)['"])"""
)
EXPRESS_RECV_RE = re.compile(
    r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:"""
    r"""express\s*\(|(?:express|require\(\s*['"]express['"]\s*\))\s*\.\s*Router\s*\(|Router\s*\()"""
)
FASTIFY_RECV_RE = re.compile(
    r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:require\(\s*['"]fastify['"]\s*\)|fastify|Fastify)\s*\("""
)
JS_ROUTE_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*\.\s*(get|post|put|patch|delete|options|head|all)\s*\(")
JS_USE_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*\.\s*use\s*\(")
JS_ROUTE_CHAIN_RE = re.compile(r"""([A-Za-z_$][\w$]*)\s*\.\s*route\s*\(\s*(['"`])([^'"`]+)\2\s*\)""")


def resolve_js_import(from_file, spec):
    if not spec.startswith("."):
        return None
    base = os.path.normpath(os.path.join(os.path.dirname(from_file), spec))
    candidates = [base] + [base + e for e in JS_EXT] + [os.path.join(base, "index" + e) for e in JS_EXT]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def scan_js(project):
    files = project.by_ext(JS_EXT)
    parsed = {}
    mounts = {}  # child_file -> [(parent_file, prefix, signals)]

    for f in files:
        raw = project.text(f)
        if not re.search(r"express|fastify|Router\(|\.(get|post|use)\(", raw):
            continue
        src = blank_comments(raw)
        imports = {}
        for m in JS_IMPORT_RE.finditer(src):
            name, spec = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
            imports[name] = spec
        recvs = {m.group(1): "express" for m in EXPRESS_RECV_RE.finditer(src)}
        recvs.update({m.group(1): "fastify" for m in FASTIFY_RECV_RE.finditer(src)})
        imports_express = bool(re.search(r"""['"]express['"]""", src))
        parsed[f] = (src, imports, recvs, imports_express)

        # .use(...) calls: global middleware or mounts
        for m in JS_USE_RE.finditer(src):
            recv = m.group(1)
            open_idx = m.end() - 1
            close = find_close(src, open_idx)
            if close < 0:
                continue
            args = split_args(src[open_idx + 1:close])
            if not args:
                continue
            prefix = str_literal(args[0])
            if prefix is None:
                continue
            rest = args[1:]
            child = None
            mw_names = []
            for a in rest:
                rm = re.match(r"""require\(\s*['"]([^'"]+)['"]\s*\)""", a.strip())
                target = None
                if rm:
                    target = resolve_js_import(f, rm.group(1))
                elif re.fullmatch(r"[A-Za-z_$][\w$]*", a.strip()) and a.strip() in imports:
                    target = resolve_js_import(f, imports[a.strip()])
                if target:
                    child = target
                else:
                    mw_names += arg_names(a)
            if child:
                sigs, _ = classify(mw_names)
                prior = global_signals(src, recv, m.start())
                mounts.setdefault(child, []).append((f, prefix, prior + sigs))

    memo = {}

    def prefixes(file, depth=0):
        if file in memo:
            return memo[file]
        if depth > 8 or file not in mounts:
            return [("", [])]
        out = []
        for parent, prefix, sigs in mounts[file]:
            for pp, ps in prefixes(parent, depth + 1):
                out.append((join_path(pp, prefix), ps + sigs))
        memo[file] = out
        return out

    for f, (src, imports, recvs, imports_express) in parsed.items():
        lines = LineIndex(src)
        known = dict(recvs)
        if imports_express or f in mounts:
            for default in ("app", "router"):
                known.setdefault(default, "express")
        if not known:
            continue
        nest_like = "@Controller" in src
        if nest_like:
            continue

        def emit(recv, method, path, args, at):
            fw = known[recv]
            mw = []
            for a in args[:-1]:
                mw += arg_names(a)
            sigs, public = classify(mw)
            handler = handler_name(args[-1]) if args else None
            base = global_signals(src, recv, at)
            for pfx, psigs in prefixes(f):
                project.add(fw, "ALL" if method == "all" else method, join_path(pfx, path), f,
                            lines.line(at), handler, psigs + base + sigs, public)

        for m in JS_ROUTE_RE.finditer(src):
            recv, method = m.group(1), m.group(2)
            if recv not in known:
                continue
            open_idx = m.end() - 1
            close = find_close(src, open_idx)
            if close < 0:
                continue
            args = split_args(src[open_idx + 1:close])
            if not args:
                continue
            path = str_literal(args[0])
            if path is None or not (path.startswith("/") or path == "*"):
                continue
            emit(recv, method, path, args[1:], m.start())

        for m in JS_ROUTE_CHAIN_RE.finditer(src):
            recv, path = m.group(1), m.group(3)
            if recv not in known:
                continue
            i = m.end()
            while True:
                cm = re.compile(r"\s*\.\s*(get|post|put|patch|delete|options|head|all)\s*\(").match(src, i)
                if not cm:
                    break
                open_idx = cm.end() - 1
                close = find_close(src, open_idx)
                if close < 0:
                    break
                emit(recv, cm.group(1), path, split_args(src[open_idx + 1:close]), m.start())
                i = close + 1

    scan_nest(project, files)


def global_signals(src, recv, before):
    """Auth middleware applied with recv.use(mw) (no path) before offset `before`."""
    sigs = []
    for m in re.finditer(r"\b" + re.escape(recv) + r"\s*\.\s*use\s*\(", src[:before]):
        open_idx = m.end() - 1
        close = find_close(src, open_idx)
        if close < 0:
            continue
        args = split_args(src[open_idx + 1:close])
        if args and str_literal(args[0]) is None:
            names = []
            for a in args:
                names += arg_names(a)
            s, _ = classify(names)
            sigs += [f"{recv}.use({x})" for x in s]
    return sigs


NEST_CTRL_RE = re.compile(r"@Controller\s*\(\s*(?:(['\"`])([^'\"`]*)\1|\{[^}]*?path\s*:\s*(['\"`])([^'\"`]*)\3[^}]*\})?\s*\)")
NEST_METHOD_RE = re.compile(r"@(Get|Post|Put|Patch|Delete|Options|Head|All)\s*\(\s*(?:(['\"`])([^'\"`]*)\2)?\s*\)")


def scan_nest(project, files):
    global_prefix = ""
    global_guard = None
    nest_files = []
    for f in files:
        src = project.text(f)
        gp = re.search(r"setGlobalPrefix\(\s*['\"`]([^'\"`]+)", src)
        if gp:
            global_prefix = gp.group(1)
        if "APP_GUARD" in src:
            global_guard = project.rel(f)
        if "@Controller" in src:
            nest_files.append(f)

    for f in nest_files:
        src = blank_comments(project.text(f))
        lines = LineIndex(src)
        ctrls = list(NEST_CTRL_RE.finditer(src))
        for ci, cm in enumerate(ctrls):
            prefix = cm.group(2) or cm.group(4) or ""
            class_m = re.compile(r"class\s+(\w+)").search(src, cm.end())
            if not class_m:
                continue
            body_end = ctrls[ci + 1].start() if ci + 1 < len(ctrls) else len(src)
            class_decos = src[cm.start():class_m.start()]
            class_names = [x for pair in re.findall(r"@(\w+)\s*\(([^)]*)\)", class_decos) for x in pair]
            class_sigs, class_public = classify(class_names)
            prev_end = class_m.end()
            for mm in NEST_METHOD_RE.finditer(src, class_m.end(), body_end):
                # decorator block: from end of the previous method signature to the method name
                name_m = re.compile(r"(?:async\s+)?([A-Za-z_]\w*)\s*\(").search(src, mm.end())
                while name_m and src[name_m.start() - 1:name_m.start()] == "@":
                    name_m = re.compile(r"(?:async\s+)?([A-Za-z_]\w*)\s*\(").search(src, name_m.end())
                block_start = max(prev_end, src.rfind("}", prev_end, mm.start()) + 1, src.rfind(";", prev_end, mm.start()) + 1)
                block = src[block_start:name_m.start() if name_m else mm.end()]
                deco_names = [x for pair in re.findall(r"@(\w+)\s*\(([^)]*)\)", block) for x in pair]
                sigs, public = classify(deco_names)
                all_sigs = class_sigs + sigs
                if global_guard and not (public or class_public):
                    all_sigs.append(f"APP_GUARD in {global_guard}")
                project.add("nestjs", mm.group(1), join_path(join_path(global_prefix, prefix), mm.group(3) or ""),
                            f, lines.line(mm.start()), name_m.group(1) if name_m else None,
                            all_sigs, public + class_public)
                prev_end = name_m.end() if name_m else mm.end()


# --------------------------------------------------------------------------- Python

def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted(node.func)
    return None


def const_str(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def kw(call, name):
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def str_list(node):
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [const_str(e) for e in node.elts if const_str(e)]
    return []


def depends_names(node):
    """Names passed to Depends()/Security() anywhere under node."""
    out = []
    if node is None:
        return out
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and (dotted(n.func) or "").split(".")[-1] in ("Depends", "Security"):
            if n.args:
                d = dotted(n.args[0])
                if d:
                    out.append(d if (dotted(n.func) or "").endswith("Depends") else f"Security({d})")
    return out


class PyModule:
    def __init__(self, path, rel, tree, src):
        self.path, self.rel, self.tree, self.src = path, rel, tree, src
        self.dotted = rel[:-3].replace("/", ".")
        if self.dotted.endswith(".__init__"):
            self.dotted = self.dotted[: -len(".__init__")]
        self.imports = {}  # local name -> (module_dotted, attr or None)
        self.routers = {}  # var -> {kind, prefix, signals, line}


def scan_python(project):
    mods = {}
    for f in project.by_ext({".py"}):
        src = project.text(f)
        if not re.search(r"fastapi|flask|django|rest_framework|urlpatterns", src, re.I):
            continue
        try:
            tree = ast.parse(src, filename=f)
        except SyntaxError as exc:
            project.warnings.append(f"python parse error in {project.rel(f)}:{exc.lineno}: {exc.msg}")
            continue
        mods[f] = PyModule(f, project.rel(f), tree, src)
    if not mods:
        return

    # Index all python modules (including ones we did not parse) for import resolution.
    by_dotted = {}
    for f in project.by_ext({".py"}):
        rel = project.rel(f)[:-3].replace("/", ".")
        if rel.endswith(".__init__"):
            rel = rel[: -len(".__init__")]
        by_dotted[rel] = f

    def find_module(name):
        if name in by_dotted:
            return by_dotted[name]
        hits = [f for d, f in by_dotted.items() if d.endswith("." + name)]
        return hits[0] if len(hits) == 1 else None

    for m in mods.values():
        pkg = m.dotted.split(".")
        if not m.rel.endswith("__init__.py"):
            pkg = pkg[:-1]
        for node in ast.walk(m.tree):
            if isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:
                    parent = pkg[: len(pkg) - (node.level - 1)] if node.level > 1 else pkg
                    base = ".".join([p for p in parent if p] + ([base] if base else []))
                for a in node.names:
                    m.imports[a.asname or a.name] = (base, a.name)
            elif isinstance(node, ast.Import):
                for a in node.names:
                    m.imports[a.asname or a.name.split(".")[0]] = (a.name if a.asname else a.name.split(".")[0], None)
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                ctor = (dotted(node.value.func) or "").split(".")[-1]
                if ctor in ("FastAPI", "APIRouter", "Flask", "Blueprint"):
                    prefix = const_str(kw(node.value, "prefix") or kw(node.value, "url_prefix")) or ""
                    sigs, _ = classify(depends_names(kw(node.value, "dependencies")))
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            m.routers[t.id] = {"kind": ctor, "prefix": prefix, "signals": sigs, "line": node.lineno}

    def resolve_ref(m, expr):
        """(file, var) for a router expression, or None."""
        if isinstance(expr, ast.Name):
            if expr.id in m.routers:
                return (m.path, expr.id)
            if expr.id in m.imports:
                mod, attr = m.imports[expr.id]
                f = find_module(mod)
                if f and attr:
                    return (f, attr)
        if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
            name = expr.value.id
            if name in m.imports:
                mod, attr = m.imports[name]
                f = find_module(f"{mod}.{attr}" if attr else mod) or (find_module(mod) if not attr else None)
                if f:
                    return (f, expr.attr)
        return None

    includes = {}  # child ref -> [(parent ref, prefix or None, signals)]
    for m in mods.values():
        for node in ast.walk(m.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr in ("include_router", "register_blueprint") and node.args:
                parent = resolve_ref(m, node.func.value)
                child = resolve_ref(m, node.args[0])
                if not child:
                    continue
                pfx = kw(node, "prefix") or kw(node, "url_prefix")
                sigs, _ = classify(depends_names(kw(node, "dependencies")))
                includes.setdefault(child, []).append((parent, const_str(pfx) if pfx is not None else None, sigs))
            # bp.before_request(check_auth)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr == "before_request" and node.args:
                ref = resolve_ref(m, node.func.value)
                name = dotted(node.args[0])
                if ref and ref[0] in mods and ref[1] in mods[ref[0]].routers and name:
                    s, _ = classify([name])
                    mods[ref[0]].routers[ref[1]]["signals"] += [f"before_request({x})" for x in s]

    def router_info(ref):
        m = mods.get(ref[0])
        return m.routers.get(ref[1]) if m else None

    memo = {}

    def prefixes(ref, depth=0):
        if ref in memo:
            return memo[ref]
        info = router_info(ref) or {"kind": "?", "prefix": "", "signals": []}
        out = []
        if depth < 8 and ref in includes:
            for parent, inc_prefix, sigs in includes[ref]:
                parents = prefixes(parent, depth + 1) if parent else [("", [])]
                if info["kind"] == "Blueprint" and inc_prefix is not None:
                    own = inc_prefix  # register_blueprint(url_prefix=) overrides Blueprint(url_prefix=)
                else:
                    own = join_path(inc_prefix or "", info["prefix"]) if inc_prefix else info["prefix"]
                for pp, ps in parents:
                    out.append((join_path(pp, own), ps + sigs + info["signals"]))
        if not out:
            out = [(info["prefix"], list(info["signals"]))]
        memo[ref] = out
        return out

    # Decorated route functions (FastAPI / Flask)
    for m in mods.values():
        before_request_sigs = {}
        for node in ast.walk(m.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if isinstance(dec, ast.Attribute) and dec.attr == "before_request":
                    ref = resolve_ref(m, dec.value)
                    names = [node.name] + [dotted(c.func) for c in ast.walk(node) if isinstance(c, ast.Call)]
                    s, _ = classify(names)
                    if ref and s:
                        before_request_sigs.setdefault(ref, []).append(f"before_request:{node.name}")
        for node in ast.walk(m.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)):
                    continue
                attr = dec.func.attr
                if attr not in HTTP_METHODS + ["route", "api_route"]:
                    continue
                ref = resolve_ref(m, dec.func.value)
                info = router_info(ref) if ref else None
                if info:
                    fw = "fastapi" if info["kind"] in ("FastAPI", "APIRouter") else "flask"
                elif re.search(r"^\s*(from|import)\s+fastapi", m.src, re.M):
                    fw, ref = "fastapi", (m.path, dotted(dec.func.value))
                elif re.search(r"^\s*(from|import)\s+flask", m.src, re.M):
                    fw, ref = "flask", (m.path, dotted(dec.func.value))
                else:
                    continue
                path = const_str(dec.args[0]) if dec.args else const_str(kw(dec, "path") or kw(dec, "rule"))
                if path is None:
                    continue
                if attr in HTTP_METHODS:
                    methods = [attr.upper()]
                else:
                    methods = [x.upper() for x in str_list(kw(dec, "methods"))] or ["GET"]
                other_decos = [dotted(d) for d in node.decorator_list if d is not dec]
                names = other_decos + depends_names(kw(dec, "dependencies")) + depends_names(node.args)
                sigs, public = classify(names)
                sigs += before_request_sigs.get(ref, [])
                for pfx, psigs in prefixes(ref):
                    for meth in methods:
                        project.add(fw, meth, join_path(pfx, path), m.path, node.lineno, node.name,
                                    psigs + sigs, public)

    scan_django(project, mods, find_module)


DRF_ACTIONS = {
    "list": ("GET", False), "create": ("POST", False), "retrieve": ("GET", True),
    "update": ("PUT", True), "partial_update": ("PATCH", True), "destroy": ("DELETE", True),
}
DRF_BASES = {
    "ModelViewSet": list(DRF_ACTIONS),
    "ReadOnlyModelViewSet": ["list", "retrieve"],
}


def scan_django(project, mods, find_module):
    url_mods = [m for m in mods.values() if "urlpatterns" in m.src]
    if not url_mods:
        return

    # Global defaults from settings
    settings_src = "\n".join(m.src for m in mods.values() if "settings" in m.rel) + "\n".join(
        project.text(f) for f in project.files if f.endswith(".py") and "settings" in os.path.basename(f))
    drf_default = None
    dp = re.search(r"DEFAULT_PERMISSION_CLASSES['\"]?\s*:\s*[\[(]([^\])]*)", settings_src)
    if dp:
        s, p = classify(re.findall(r"[\w.]+", dp.group(1)))
        drf_default = "DEFAULT_PERMISSION_CLASSES=" + ",".join(s) if s and not p else None
    login_mw = "LoginRequiredMiddleware" in settings_src

    # Index class/function definitions by name
    defs = {}
    for m in mods.values():
        for node in ast.walk(m.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                defs.setdefault(node.name, []).append((m, node))

    def lookup(name, near):
        cands = defs.get(name, [])
        if not cands:
            return None, None
        same_dir = [c for c in cands if os.path.dirname(c[0].path) == os.path.dirname(near)]
        return (same_dir or cands)[0]

    def view_auth(node, is_drf):
        names, public = [], []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in node.decorator_list:
                names.append(dotted(d))
                if isinstance(d, ast.Call):
                    for a in d.args:
                        names += [dotted(e) for e in getattr(a, "elts", [])]
        elif isinstance(node, ast.ClassDef):
            names += [dotted(b) for b in node.bases]
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id in ("permission_classes", "authentication_classes") for t in stmt.targets):
                    names += [dotted(e) for e in getattr(stmt.value, "elts", [])]
                    if not getattr(stmt.value, "elts", None) and any(t.id == "permission_classes" for t in stmt.targets if isinstance(t, ast.Name)):
                        public.append("permission_classes=[]")
        sigs, pub = classify([n for n in names if n and not n.endswith(("api_view", "action"))])
        public += pub
        if not sigs and not public:
            if is_drf and drf_default:
                sigs = [drf_default]
            elif login_mw:
                sigs = ["LoginRequiredMiddleware"]
        return sigs, public

    def func_methods(node):
        for d in node.decorator_list:
            name = (dotted(d) or "").split(".")[-1]
            if name in ("api_view", "require_http_methods") and isinstance(d, ast.Call) and d.args:
                return [x.upper() for x in str_list(d.args[0])] or ["GET"], name == "api_view"
            if name in ("require_GET", "require_safe"):
                return ["GET"], False
            if name == "require_POST":
                return ["POST"], False
        return ["ANY"], False

    def add_view(path, view_expr, m, line):
        is_class = isinstance(view_expr, ast.Call) and isinstance(view_expr.func, ast.Attribute) and view_expr.func.attr == "as_view"
        name_expr = view_expr.func.value if is_class else view_expr
        name = (dotted(name_expr) or "").split(".")[-1]
        vm, node = lookup(name, m.path)
        if node is None:
            project.add("django", "ANY", path, m.path, line, name or None, [], default="unknown")
            return
        if isinstance(node, ast.ClassDef):
            meths = [s.name.upper() for s in node.body if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))
                     and s.name in HTTP_METHODS]
            is_drf = any("APIView" in (dotted(b) or "") or "Generic" in (dotted(b) or "") for b in node.bases)
            sigs, public = view_auth(node, is_drf)
            for meth in meths or ["ANY"]:
                project.add("django-drf" if is_drf else "django", meth, path, vm.path, node.lineno, name, sigs, public)
        else:
            meths, is_drf = func_methods(node)
            sigs, public = view_auth(node, is_drf)
            for meth in meths:
                project.add("django-drf" if is_drf else "django", meth, path, vm.path, node.lineno, name, sigs, public)

    def add_viewset(prefix, vs_expr, m, line):
        name = (dotted(vs_expr) or "").split(".")[-1]
        vm, node = lookup(name, m.path)
        if node is None or not isinstance(node, ast.ClassDef):
            project.add("django-drf", "ANY", join_path(prefix, ""), m.path, line, name, [], default="unknown")
            return
        actions = set()
        for b in node.bases:
            actions.update(DRF_BASES.get((dotted(b) or "").split(".")[-1], []))
        sigs, public = view_auth(node, True)
        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if stmt.name in DRF_ACTIONS:
                    actions.add(stmt.name)
                for d in stmt.decorator_list:
                    if isinstance(d, ast.Call) and (dotted(d.func) or "").endswith("action"):
                        detail = kw(d, "detail")
                        is_detail = isinstance(detail, ast.Constant) and detail.value is True
                        path = join_path(prefix, ("{pk}/" if is_detail else "") + (const_str(kw(d, "url_path")) or stmt.name) + "/")
                        for meth in [x.upper() for x in str_list(kw(d, "methods"))] or ["GET"]:
                            s2, p2 = classify([dotted(e) for e in getattr(kw(d, "permission_classes"), "elts", [])])
                            project.add("django-drf", meth, path, vm.path, stmt.lineno, f"{name}.{stmt.name}",
                                        s2 or sigs, p2 or public)
        for act in sorted(actions):
            meth, detail = DRF_ACTIONS[act]
            project.add("django-drf", meth, join_path(prefix, "{pk}/" if detail else ""), vm.path, node.lineno,
                        f"{name}.{act}", sigs, public)

    # Build include graph: urls module -> [(parent module, prefix)]
    included = {}
    drf_routers = {}  # (file, var) -> [(prefix, viewset_expr, module, line)]
    for m in url_mods:
        for node in ast.walk(m.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "register" and len(node.args) >= 2:
                p = const_str(node.args[0])
                if p is not None and isinstance(node.func.value, ast.Name):
                    drf_routers.setdefault((m.path, node.func.value.id), []).append((p.strip("^$"), node.args[1], m, node.lineno))

    patterns = {}
    for m in url_mods:
        entries = []
        for node in ast.walk(m.tree):
            if isinstance(node, (ast.Assign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(isinstance(t, ast.Name) and t.id == "urlpatterns" for t in targets):
                    value = node.value
                    if isinstance(value, ast.BinOp):
                        elts = []
                        for side in (value.left, value.right):
                            elts += getattr(side, "elts", [])
                    else:
                        elts = getattr(value, "elts", [])
                    entries += [e for e in elts if isinstance(e, ast.Call)]
        patterns[m.path] = entries
        for e in entries:
            fname = (dotted(e.func) or "").split(".")[-1]
            if fname not in ("path", "re_path", "url") or len(e.args) < 2:
                continue
            route = (const_str(e.args[0]) or "").strip("^$")
            target = e.args[1]
            if isinstance(target, ast.Call) and (dotted(target.func) or "").endswith("include") and target.args:
                arg = target.args[0]
                mod = const_str(arg)
                if mod:
                    f = find_module(mod)
                    if f:
                        included.setdefault(f, []).append((m.path, route))

    memo = {}

    def prefixes(f, depth=0):
        if f in memo:
            return memo[f]
        out = []
        if depth < 8:
            for parent, route in included.get(f, []):
                for pp in prefixes(parent, depth + 1):
                    out.append(join_path(pp, route))
        memo[f] = out or ["/"]
        return memo[f]

    for m in url_mods:
        for pfx in prefixes(m.path):
            for e in patterns.get(m.path, []):
                fname = (dotted(e.func) or "").split(".")[-1]
                if fname not in ("path", "re_path", "url") or len(e.args) < 2:
                    continue
                route = (const_str(e.args[0]) or "").strip("^$")
                target = e.args[1]
                full = join_path(pfx, route)
                if isinstance(target, ast.Call) and (dotted(target.func) or "").endswith("include"):
                    arg = target.args[0] if target.args else None
                    if isinstance(arg, ast.Attribute) and arg.attr == "urls" and isinstance(arg.value, ast.Name):
                        for reg_prefix, vs, rm, line in drf_routers.get((m.path, arg.value.id), []):
                            add_viewset(join_path(full, reg_prefix + "/"), vs, rm, line)
                    continue
                add_view(full, target, m, e.lineno)


# --------------------------------------------------------------------------- Java / Kotlin (Spring)

SPRING_CLASS_RE = re.compile(r"@(RestController|Controller)\b")
SPRING_MAP_RE = re.compile(r"@(Get|Post|Put|Patch|Delete|Request)Mapping\b(\s*\()?")


def annotation_path(src, start):
    """Path from @XMapping(...) whose '(' is at start, or '' if none."""
    close = find_close(src, start)
    if close < 0:
        return "", start
    body = src[start + 1:close]
    m = re.search(r'(?:^|[,(\s])(?:value|path)\s*=\s*\{?\s*"([^"]*)"', body) or re.match(r'\s*\{?\s*"([^"]*)"', body)
    return (m.group(1) if m else ""), close


def scan_spring(project):
    files = project.by_ext({".java", ".kt"})
    global_cfg = None
    for f in files:
        src = project.text(f)
        m = re.search(r"SecurityFilterChain|WebSecurityConfigurerAdapter|@EnableWebSecurity", src)
        if m:
            global_cfg = f"Spring Security config in {project.rel(f)}:{LineIndex(src).line(m.start())}"
            break
    for f in files:
        raw = project.text(f)
        if not SPRING_CLASS_RE.search(raw):
            continue
        src = blank_comments(raw)
        lines = LineIndex(src)
        cls = re.search(r"\bclass\s+(\w+)", src)
        if not cls:
            continue
        header = src[:cls.start()]
        class_prefix = ""
        hm = re.search(r"@RequestMapping\s*\(", header)
        if hm:
            class_prefix, _ = annotation_path(src, hm.end() - 1)
        class_sigs, class_public = classify(re.findall(r"@(\w+)", header))
        prev = cls.end()
        for mm in SPRING_MAP_RE.finditer(src, cls.end()):
            kind = mm.group(1)
            path, end = ("", mm.end())
            body = ""
            if mm.group(2):
                open_idx = mm.end() - 1
                path, end = annotation_path(src, open_idx)
                body = src[open_idx:end + 1]
            if kind == "Request":
                ms = re.findall(r"RequestMethod\.(\w+)", body) or ["ANY"]
            else:
                ms = [kind.upper()]
            name_m = re.compile(r"(?:fun\s+|[\w<>\[\],.?]+\s+)([a-zA-Z_]\w*)\s*\(").search(src, end + 1)
            while name_m and src[name_m.start():].lstrip().startswith("@"):
                name_m = re.compile(r"(?:fun\s+|[\w<>\[\],.?]+\s+)([a-zA-Z_]\w*)\s*\(").search(src, name_m.end())
            block_start = max(prev, src.rfind("}", prev, mm.start()) + 1, src.rfind(";", prev, mm.start()) + 1)
            block = src[block_start:name_m.start() if name_m else end]
            sigs, public = classify(re.findall(r"@(\w+)", block))
            for meth in ms:
                project.add("spring", meth, join_path(class_prefix, path), f, lines.line(mm.start()),
                            name_m.group(1) if name_m else None, class_sigs + sigs, public + class_public,
                            default="unknown" if global_cfg else None,
                            notes=[global_cfg] if global_cfg else ())
            prev = name_m.end() if name_m else end


# --------------------------------------------------------------------------- Go

GO_GROUP_RE = re.compile(r"(\w+)\s*:?=\s*(\w+)\.(Group|Route)\(\s*\"([^\"]*)\"")
GO_USE_RE = re.compile(r"\b(\w+)\.Use\(")
GO_ROUTE_RE = re.compile(
    r"\b(\w+)(?:\.With\(([^)]*)\))?\.(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|Any|Get|Post|Put|Patch|Delete|Options|Head|HandleFunc|Handle)\(\s*\""
)


def scan_go(project):
    for f in project.by_ext({".go"}):
        raw = project.text(f)
        if not re.search(r"net/http|gin-gonic|labstack/echo|go-chi|gorilla/mux", raw):
            continue
        fw = ("gin" if "gin-gonic" in raw else "echo" if "labstack/echo" in raw else
              "chi" if "go-chi" in raw else "gorilla" if "gorilla/mux" in raw else "net/http")
        src = blank_comments(raw)
        lines = LineIndex(src)
        groups = {}  # var -> (prefix, signals)
        for gm in GO_GROUP_RE.finditer(src):
            var, parent, _, prefix = gm.groups()
            pp, ps = groups.get(parent, ("", []))
            close = find_close(src, src.index("(", gm.start(3)))
            extra = split_args(src[src.index("(", gm.start(3)) + 1:close])[1:] if close > 0 else []
            names = [n for a in extra for n in re.findall(r"[A-Za-z_][\w.]*", a)]
            s, _ = classify(names)
            groups[var] = (join_path(pp, prefix), ps + s)
        uses = []  # (offset, var, signals)
        for um in GO_USE_RE.finditer(src):
            close = find_close(src, um.end() - 1)
            names = re.findall(r"[A-Za-z_][\w.]*", src[um.end():close]) if close > 0 else []
            s, _ = classify(names)
            uses.append((um.start(), um.group(1), [f"{um.group(1)}.Use({x})" for x in s]))

        for rm in GO_ROUTE_RE.finditer(src):
            var, with_args, meth = rm.groups()
            open_idx = rm.end() - 2
            close = find_close(src, open_idx)
            if close < 0:
                continue
            args = split_args(src[open_idx + 1:close])
            path = args[0].strip().strip('"')
            if meth in ("HandleFunc", "Handle"):
                pm = re.match(r"^([A-Z]+)\s+(/.*)$", path)  # Go 1.22 "GET /path"
                if pm:
                    method, path = pm.groups()
                else:
                    mm = re.compile(r"\s*\.Methods\(([^)]*)\)").match(src, close + 1)
                    method = ",".join(re.findall(r'"(\w+)"', mm.group(1))) if mm else "ANY"
            else:
                method = "ANY" if meth == "Any" else meth.upper()
            if not path.startswith("/"):
                continue
            prefix, gsig = groups.get(var, ("", []))
            names = [n for a in args[1:] for n in re.findall(r"[A-Za-z_][\w.]*", a)]
            if with_args:
                names += re.findall(r"[A-Za-z_][\w.]*", with_args)
            sigs, public = classify(names)
            for off, uvar, usig in uses:
                if off < rm.start() and (uvar == var or (var in groups and uvar in ("r", "router", "e", "app", "mux"))):
                    sigs += usig
            handler = None
            if len(args) > 1:
                hm = re.findall(r"[A-Za-z_][\w.]*", args[-1])
                handler = hm[-1] if hm else None
                if args[-1].strip().startswith("func"):
                    handler = "<inline>"
            for m_ in method.split(","):
                project.add(fw, m_, join_path(prefix, path), f, lines.line(rm.start()), handler, gsig + sigs, public)


# --------------------------------------------------------------------------- main

def discover(root, include_tests=False):
    project = Project(root, include_tests)
    for scanner in (scan_js, scan_python, scan_spring, scan_go):
        try:
            scanner(project)
        except Exception as exc:  # keep going: partial inventory beats none
            project.warnings.append(f"{scanner.__name__} failed: {type(exc).__name__}: {exc}")
    seen, routes = set(), []
    for r in sorted(project.routes, key=lambda r: (r["path_normalized"], r["method"], r["file"], r["line"])):
        key = (r["method"], r["path"], r["file"], r["line"])
        if key not in seen:
            seen.add(key)
            routes.append(r)
    if not routes:
        project.warnings.append("no routes found; the framework may be unsupported or routes are built dynamically")
    return {
        "tool": "securitykit-discover-routes",
        "version": VERSION,
        "root": ".",
        "frameworks": sorted(project.frameworks),
        "summary": {
            "routes": len(routes),
            "auth_yes": sum(r["auth"] == "yes" for r in routes),
            "auth_no": sum(r["auth"] == "no" for r in routes),
            "auth_unknown": sum(r["auth"] == "unknown" for r in routes),
        },
        "routes": routes,
        "warnings": project.warnings,
    }


def print_table(result):
    rows = [(r["method"], r["path"], f'{r["file"]}:{r["line"]}', r["auth"]) for r in result["routes"]]
    widths = [max([len(h)] + [len(row[i]) for row in rows]) for i, h in enumerate(("METHOD", "PATH", "HANDLER", "AUTH"))]
    fmt = "  ".join("{:<%d}" % w for w in widths)
    print(fmt.format("METHOD", "PATH", "HANDLER", "AUTH"))
    for row in rows:
        print(fmt.format(*row))
    for w in result["warnings"]:
        print(f"warning: {w}", file=sys.stderr)


def main(argv=None):
    ap = argparse.ArgumentParser(description="List HTTP endpoints in a project (SecurityKit).")
    ap.add_argument("--root", default=".", help="project root (default: .)")
    ap.add_argument("--out", help="write JSON here instead of stdout")
    ap.add_argument("--format", choices=["json", "table"], default="json")
    ap.add_argument("--include-tests", action="store_true", help="also scan test files")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)
    if not os.path.isdir(args.root):
        print(f"error: not a directory: {args.root}", file=sys.stderr)
        return 2
    result = discover(args.root, args.include_tests)
    if args.format == "table" and not args.out:
        print_table(result)
        return 0
    text = json.dumps(result, indent=2)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"wrote {result['summary']['routes']} routes to {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
SecurityKit phantom dependency finder (read-only, offline, standard library only).

Hallucinated package names show up in two places: code that imports a package no manifest declares, and manifests
that declare a package the lockfile never resolved (it was added by hand or by an assistant and never installed).
This script lists both, for JavaScript/TypeScript (package.json + package-lock/pnpm-lock/yarn.lock/bun.lock) and
Python (requirements*.txt, pyproject.toml, Pipfile, setup.py + poetry.lock/uv.lock/Pipfile.lock). Every entry is a
CANDIDATE: aliases, workspace packages and generated modules are common false positives for the agent to drop.

  python3 phantom_deps.py --root . --out .securitykit/ai-code-deps.json
"""

import argparse
import json
import os
import re
import sys

from sk_outputs import prepare_output

VERSION = "0.1.0"

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "target", "out", ".next", ".nuxt", ".svelte-kit", ".output",
    "__pycache__", ".venv", "venv", "env", ".tox", ".mypy_cache", ".pytest_cache", ".securitykit", ".claude", ".codex",
    "coverage", ".idea", ".vscode", "bin", "obj", "Pods", ".gradle", ".terraform", "site-packages", ".turbo", ".vercel",
}
JS_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte", ".astro"}
NODE_BUILTINS = {
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants", "crypto", "dgram",
    "diagnostics_channel", "dns", "domain", "events", "fs", "http", "http2", "https", "inspector", "module", "net", "os",
    "path", "perf_hooks", "process", "punycode", "querystring", "readline", "repl", "stream", "string_decoder", "sys",
    "timers", "tls", "trace_events", "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib", "test", "sqlite",
}
# Specifier prefixes that are never npm packages (path aliases, framework virtual modules, protocols).
JS_NON_PACKAGE = re.compile(r"^(\.|/|~|#|@/|\$|virtual:|node:|bun:|deno:|npm:|jsr:|https?:|data:|astro:|\w+:)")
JS_IMPORT = re.compile(r"""(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\(\s*|\bimport\s+)['"]([^'"\s]+)['"]""")
# Import name -> distribution name, for the common cases where they differ.
PY_ALIASES = {
    "yaml": "pyyaml", "pil": "pillow", "cv2": "opencv-python", "sklearn": "scikit-learn", "bs4": "beautifulsoup4",
    "dateutil": "python-dateutil", "dotenv": "python-dotenv", "jwt": "pyjwt", "attr": "attrs", "crypto": "pycryptodome",
    "openssl": "pyopenssl", "magic": "python-magic", "docx": "python-docx", "pptx": "python-pptx", "fitz": "pymupdf",
    "mysqldb": "mysqlclient", "serial": "pyserial", "usb": "pyusb", "telegram": "python-telegram-bot",
    "discord": "discord-py", "multipart": "python-multipart", "jose": "python-jose", "slugify": "python-slugify",
    "gi": "pygobject", "win32api": "pywin32", "win32con": "pywin32", "pkg_resources": "setuptools", "zmq": "pyzmq",
    "socketio": "python-socketio", "engineio": "python-engineio", "websocket": "websocket-client", "google": "google-*",
    "googleapiclient": "google-api-python-client", "psycopg2": "psycopg2-binary", "kafka": "kafka-python",
    "dns": "dnspython", "ldap": "python-ldap", "github": "pygithub", "git": "gitpython", "markdown": "markdown",
    "mpl_toolkits": "matplotlib", "skimage": "scikit-image", "nacl": "pynacl", "jinja2": "jinja2", "lxml": "lxml",
    "rest_framework": "djangorestframework", "corsheaders": "django-cors-headers", "environ": "django-environ",
    "flask_cors": "flask-cors", "flask_sqlalchemy": "flask-sqlalchemy", "flask_login": "flask-login",
    "flask_wtf": "flask-wtf", "flask_limiter": "flask-limiter", "jwt_extended": "flask-jwt-extended",
    "typing_extensions": "typing-extensions", "pydantic_settings": "pydantic-settings", "huggingface_hub": "huggingface-hub",
}


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        for f in sorted(filenames):
            yield os.path.relpath(os.path.join(dirpath, f), root).replace(os.sep, "/")


def read(root, rel, limit=2_000_000):
    try:
        with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def norm_py(name):
    return re.sub(r"[-_.]+", "-", name.strip().lower())


# --------------------------------------------------------------------------- JavaScript / TypeScript

def js_package_name(spec):
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") and len(parts) > 1 else parts[0]


def scan_js(root, files, out):
    manifests = [f for f in files if os.path.basename(f) == "package.json"]
    if not manifests:
        return
    declared, workspace = {}, set()
    for m in manifests:
        try:
            data = json.loads(read(root, m))
        except ValueError:
            out["warnings"].append(f"could not parse {m}")
            continue
        if data.get("name"):
            workspace.add(data["name"])
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for name in (data.get(key) or {}):
                declared.setdefault(name, m)
    aliases = set()
    for f in files:
        if os.path.basename(f).startswith(("tsconfig", "jsconfig")) and f.endswith(".json"):
            for key in re.findall(r'"([^"]+)"\s*:\s*\[', read(root, f)):
                aliases.add(key.rstrip("*").rstrip("/"))
    aliases.discard("")

    seen = {}
    for f in files:
        if os.path.splitext(f)[1].lower() not in JS_EXT:
            continue
        for i, line in enumerate(read(root, f).splitlines(), 1):
            if len(line) > 2000:
                continue
            for spec in JS_IMPORT.findall(line):
                if JS_NON_PACKAGE.match(spec) or any(spec == a or spec.startswith(a + "/") for a in aliases):
                    continue
                pkg = js_package_name(spec)
                if pkg in NODE_BUILTINS or pkg in declared or pkg in workspace or f"@types/{pkg}" in declared:
                    continue
                seen.setdefault(pkg, []).append(f"{f}:{i}")
    for pkg, where in sorted(seen.items()):
        out["undeclared_imports"].append({"ecosystem": "npm", "package": pkg, "locations": where[:5], "count": len(where)})

    locks = [f for f in files if os.path.basename(f) in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "npm-shrinkwrap.json")]
    out["ecosystems"]["npm"] = {"manifests": manifests, "lockfiles": locks, "declared": len(declared)}
    if not locks:
        out["warnings"].append("npm: no lockfile found, so declared-but-never-installed packages cannot be checked")
        return
    lock_text = "\n".join(read(root, lf) for lf in locks)
    for name, manifest in sorted(declared.items()):
        e = re.escape(name)
        if not re.search(rf"node_modules/{e}[\"/]|[\"'\s/]{e}@|^{e}@|\"{e}\"\s*:|^\s+'?{e}'?:", lock_text, re.M):
            out["not_in_lockfile"].append({"ecosystem": "npm", "package": name, "manifest": manifest})


# --------------------------------------------------------------------------- Python

def py_declared(root, files):
    declared, manifests = {}, []
    for f in files:
        base = os.path.basename(f)
        text = None
        if re.match(r"requirements[^/]*\.(txt|in)$", base):
            text = read(root, f)
            names = [re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", ln).group(1) for ln in text.splitlines()
                     if re.match(r"\s*[A-Za-z0-9]", ln) and not ln.strip().startswith(("-", "#"))]
        elif base == "pyproject.toml":
            text = read(root, f)
            names = re.findall(r"^\s*['\"]([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*[<>=!~;\s'\"]", text, re.M)
            names += re.findall(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*(?:['\"{])", text.split("[tool.poetry.dependencies]", 1)[1], re.M) \
                if "[tool.poetry.dependencies]" in text else []
        elif base == "Pipfile":
            text = read(root, f)
            names = re.findall(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=", text, re.M)
        elif base == "setup.py":
            text = read(root, f)
            names = re.findall(r"['\"]([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:[<>=!~]=?[^'\"]*)?['\"]", text.split("install_requires", 1)[1][:3000]) \
                if "install_requires" in text else []
        else:
            continue
        manifests.append(f)
        for n in names:
            if n.lower() not in ("python", "requires", "name", "version"):
                declared.setdefault(norm_py(n), f)
    return declared, manifests


def scan_py(root, files, out):
    declared, manifests = py_declared(root, files)
    if not manifests:
        return
    stdlib = set(getattr(sys, "stdlib_module_names", ())) | {"__future__"}
    local = set()
    for f in files:
        parts = f.split("/")
        local.update(p for p in parts[:-1])
        if f.endswith(".py"):
            local.add(os.path.splitext(parts[-1])[0])
    seen = {}
    rx = re.compile(r"^\s*(?:import\s+([A-Za-z_][\w]*)|from\s+([A-Za-z_][\w]*)[\w.]*\s+import\b)")
    for f in files:
        if not f.endswith(".py"):
            continue
        for i, line in enumerate(read(root, f).splitlines(), 1):
            m = rx.match(line)
            if not m:
                continue
            mod = m.group(1) or m.group(2)
            if mod in stdlib or mod in local:
                continue
            dist = PY_ALIASES.get(mod.lower(), mod)
            candidates = {norm_py(mod), norm_py(dist), norm_py("python-" + mod), norm_py("py" + mod)}
            if dist.endswith("*") and any(d.startswith(dist[:-1]) for d in declared):
                continue
            if candidates & set(declared) or any(d.startswith(norm_py(mod) + "-") for d in declared):
                continue
            seen.setdefault(mod, []).append(f"{f}:{i}")
    for mod, where in sorted(seen.items()):
        out["undeclared_imports"].append({"ecosystem": "pypi", "package": mod, "locations": where[:5], "count": len(where)})

    locks = [f for f in files if os.path.basename(f) in ("poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock")]
    out["ecosystems"]["pypi"] = {"manifests": manifests, "lockfiles": locks, "declared": len(declared)}
    if not locks:
        return
    lock_names = {norm_py(n) for lf in locks for n in re.findall(r"(?:^name\s*=\s*\"|^\s*\")([A-Za-z0-9][A-Za-z0-9._-]*)\"", read(root, lf), re.M)}
    for name, manifest in sorted(declared.items()):
        if name not in lock_names:
            out["not_in_lockfile"].append({"ecosystem": "pypi", "package": name, "manifest": manifest})


def main(argv=None):
    ap = argparse.ArgumentParser(description="SecurityKit phantom dependency finder.")
    ap.add_argument("--root", default=".")
    ap.add_argument("--out")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"error: not a directory: {args.root}", file=sys.stderr)
        return 2
    files = list(walk(root))
    out = {"tool": "securitykit-phantom-deps", "version": VERSION, "root": ".", "ecosystems": {},
           "undeclared_imports": [], "not_in_lockfile": [], "warnings": []}
    scan_js(root, files, out)
    scan_py(root, files, out)
    if not out["ecosystems"]:
        out["warnings"].append("no package.json or Python manifest found")
    text = json.dumps(out, indent=2)
    if args.out:
        prepare_output(args.out)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"undeclared imports: {len(out['undeclared_imports'])} · not in lockfile: {len(out['not_in_lockfile'])} → {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

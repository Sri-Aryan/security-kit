#!/usr/bin/env python3
"""
SecurityKit dependency audit (offline, read-only, standard library only).

Reads manifests and lockfiles for npm/yarn/pnpm, pip/Poetry/Pipenv/uv, Go, Ruby, PHP, Rust, Maven, Gradle, .NET,
Dart and Swift, and reports CANDIDATES for the agent to confirm:

  lock        manifests without a lockfile
  pin         unpinned or open-ended versions ("*", "latest", ">=", Maven/Gradle dynamic versions)
  source      dependencies from git URLs, tarballs or local paths
  typo        names one edit away from a popular package (possible typosquat)
  confusion   extra package indexes / registries that enable dependency confusion
  known       versions known to have been hijacked or sabotaged, and unmaintained packages
  scripts     install scripts in installed node_modules packages
  update      Dependabot / Renovate configuration
  tools       local vulnerability scanners available (npm audit, pip-audit, osv-scanner, ...). This script never runs
              them: they contact advisory databases, so the agent asks the user first.

  python3 deps_audit.py --root . --out .securitykit/deps-audit.json
"""

import argparse
import json
import os
import re
import shutil
import sys

from sk_outputs import prepare_output

VERSION = "0.1.0"

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "target", "out", ".next", ".nuxt", "__pycache__", ".venv",
    "venv", "env", ".tox", ".mypy_cache", ".pytest_cache", ".securitykit", ".claude", ".codex", ".agents", "coverage",
    ".idea", ".vscode", "bin", "obj", "Pods", ".gradle", ".terraform", "site-packages", ".dart_tool",
}

# Manifest -> lockfiles that satisfy it (any one).
LOCKS = {
    "package.json": ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock"],
    "pyproject.toml": ["poetry.lock", "uv.lock", "pdm.lock", "requirements.lock", "requirements.txt"],
    "Pipfile": ["Pipfile.lock"],
    "go.mod": ["go.sum"],
    "Gemfile": ["Gemfile.lock"],
    "composer.json": ["composer.lock"],
    "Cargo.toml": ["Cargo.lock"],
    "pubspec.yaml": ["pubspec.lock"],
    "Package.swift": ["Package.resolved"],
}

POPULAR = {
    "npm": """react react-dom next vue nuxt svelte angular express koa fastify hapi nestjs lodash underscore axios
        node-fetch got request moment dayjs date-fns luxon uuid nanoid chalk commander yargs debug dotenv cors helmet
        body-parser cookie-parser jsonwebtoken jose bcrypt bcryptjs argon2 passport mongoose mongodb mysql mysql2 pg
        sqlite3 sequelize typeorm prisma knex drizzle-orm redis ioredis socket.io ws graphql apollo-server zod yup joi
        ajv typescript webpack vite rollup esbuild babel-core eslint prettier jest mocha chai vitest supertest sinon
        nodemon pm2 rimraf mkdirp glob minimist semver classnames styled-components tailwindcss postcss autoprefixer
        sass less jquery bootstrap rxjs immer redux zustand mobx formik multer sharp jimp nodemailer stripe twilio
        openai langchain puppeteer playwright cheerio jsdom marked dompurify sanitize-html xss validator qs
        cross-env concurrently husky inquirer ora winston pino morgan bunyan colors faker cross-spawn node-sass
        electron express-session connect-redis passport-local passport-jwt firebase aws-sdk crypto-js""".split(),
    "pypi": """requests urllib3 numpy pandas scipy matplotlib django flask fastapi starlette uvicorn gunicorn celery
        sqlalchemy psycopg2 psycopg2-binary pymysql pymongo redis boto3 botocore pydantic jinja2 werkzeug click
        pyyaml python-dotenv cryptography pyjwt bcrypt passlib argon2-cffi paramiko pillow beautifulsoup4 lxml
        selenium scrapy pytest tox black flake8 mypy pylint isort setuptools wheel pip virtualenv six attrs
        python-dateutil pytz certifi idna charset-normalizer httpx aiohttp openai anthropic langchain transformers
        torch tensorflow keras scikit-learn xgboost opencv-python tqdm rich typer colorama simplejson ujson orjson
        marshmallow alembic gevent eventlet twisted tornado sentry-sdk stripe twilio""".split(),
}

# Package versions publicly reported as hijacked or sabotaged, and packages no longer maintained.
KNOWN_BAD = {
    "npm": {
        "event-stream": ({"3.3.6"}, "3.3.6 shipped the flatmap-stream backdoor (2018)"),
        "flatmap-stream": (None, "malicious package (event-stream incident, 2018)"),
        "ua-parser-js": ({"0.7.29", "0.8.0", "1.0.0"}, "hijacked releases with a cryptominer/stealer (Oct 2021)"),
        "coa": ({"2.0.3", "2.0.4", "2.1.1", "2.1.3", "3.0.1", "3.1.3"}, "hijacked releases (Nov 2021)"),
        "rc": ({"1.2.9", "1.3.9", "2.3.9"}, "hijacked releases (Nov 2021)"),
        "colors": ({"1.4.1", "1.4.2", "1.4.44-liberty-2"}, "sabotaged by its author (Jan 2022)"),
        "faker": ({"6.6.6"}, "sabotaged by its author (Jan 2022); use @faker-js/faker"),
        "node-ipc": ({"10.1.1", "10.1.2", "10.1.3"}, "protestware that overwrote files (Mar 2022)"),
        "request": (None, "deprecated and unmaintained since 2020"),
        "node-uuid": (None, "deprecated; use uuid"),
        "crypto-js": (None, "discontinued (2023); use WebCrypto or node:crypto"),
        "node-serialize": (None, "unsafe deserialization (RCE) by design"),
    },
    "pypi": {
        "pycrypto": (None, "unmaintained since 2013; use cryptography or pycryptodome"),
        "ctx": (None, "hijacked to steal environment variables (May 2022)"),
    },
}

VULN_TOOLS = [
    ("npm", "npm audit --omit=dev", "package-lock.json"),
    ("pnpm", "pnpm audit --prod", "pnpm-lock.yaml"),
    ("yarn", "yarn npm audit", "yarn.lock"),
    ("pip-audit", "pip-audit -r requirements.txt", None),
    ("osv-scanner", "osv-scanner scan source -r .", None),
    ("govulncheck", "govulncheck ./...", "go.mod"),
    ("bundle-audit", "bundle-audit check --update", "Gemfile.lock"),
    ("cargo-audit", "cargo audit", "Cargo.lock"),
    ("composer", "composer audit", "composer.lock"),
    ("dotnet", "dotnet list package --vulnerable --include-transitive", None),
    ("trivy", "trivy fs --scanners vuln .", None),
    ("grype", "grype dir:.", None),
]


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        yield ("" if rel_dir == "." else rel_dir + "/"), set(filenames)


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(3_000_000)
    except OSError:
        return ""


def load_toml(text):
    try:
        import tomllib  # Python 3.11+
        return tomllib.loads(text)
    except ImportError:
        return None
    except Exception:
        return {}


def damerau1(a, b):
    """True if a and b differ by exactly one insertion, deletion, substitution or adjacent swap."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    if len(a) > len(b):
        a, b = b, a
    return any(a == b[:i] + b[i + 1:] for i in range(len(b)))


def lookalike(name, ecosystem):
    popular = POPULAR.get(ecosystem, [])
    bare = name.split("/")[-1].lower()
    if bare in popular or name.lower() in popular:
        return None
    norm = lambda s: s.replace("-", "").replace("_", "").replace(".", "")
    for p in popular:
        if len(p) >= 5 and (damerau1(bare, p) or (norm(bare) == norm(p) and bare != p)):
            return p
    return None


# --------------------------------------------------------------------------- parsers: return [(name, spec, dev)]

def npm_deps(text):
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out = []
    for key, dev in (("dependencies", False), ("devDependencies", True), ("optionalDependencies", False), ("peerDependencies", False)):
        for name, spec in (data.get(key) or {}).items():
            out.append((name, str(spec), dev))
    return out


def requirements_deps(text):
    out = []
    for raw in text.splitlines():
        line = raw.split(" #")[0].strip()
        if not line or line.startswith("#") or line.startswith(("-r ", "-c ", "--requirement", "--constraint")):
            continue
        if line.startswith(("--extra-index-url", "--index-url", "-i ", "--find-links", "-f ", "--trusted-host")):
            out.append(("<index option>", line, False))
            continue
        if line.startswith(("-e ", "--editable")) or re.match(r"(git\+|https?://|file:|\.{0,2}/)", line):
            out.append((line.split("#egg=")[-1] if "#egg=" in line else line, line, False))
            continue
        m = re.match(r"([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(.*)$", line)
        if m:
            out.append((m.group(1), m.group(3).split(";")[0].strip(), False))
    return out


def pyproject_deps(text):
    data = load_toml(text)
    if data is None:
        return [(m.group(1), m.group(2), False) for m in re.finditer(r"^\s*['\"]([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*([^'\";]*)", text, re.M)]
    out = []
    for dep in (data.get("project") or {}).get("dependencies", []) or []:
        m = re.match(r"([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*([^;]*)", dep)
        if m:
            out.append((m.group(1), m.group(3).strip(), False))
    for group, deps in ((data.get("project") or {}).get("optional-dependencies") or {}).items():
        for dep in deps:
            m = re.match(r"([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*([^;]*)", dep)
            if m:
                out.append((m.group(1), m.group(3).strip(), True))
    poetry = ((data.get("tool") or {}).get("poetry") or {})
    for key, dev in (("dependencies", False), ("dev-dependencies", True)):
        for name, spec in (poetry.get(key) or {}).items():
            if name != "python":
                out.append((name, json.dumps(spec) if isinstance(spec, dict) else str(spec), dev))
    return out


def toml_table_deps(text, tables):
    data = load_toml(text)
    out = []
    if not data:
        return out
    for table, dev in tables:
        cur = data
        for part in table.split("."):
            cur = (cur or {}).get(part) if isinstance(cur, dict) else None
        for name, spec in (cur or {}).items():
            out.append((name, json.dumps(spec) if isinstance(spec, dict) else str(spec), dev))
    return out


def gomod_deps(text):
    out = []
    for m in re.finditer(r"^\s*(?:require\s+)?([\w.\-/]+\.[\w.\-/]+)\s+(v[\w.\-+]+)", text, re.M):
        out.append((m.group(1), m.group(2), False))
    for m in re.finditer(r"^\s*(?:replace\s+)?[\w.\-/]+(?:\s+v[\w.\-+]+)?\s*=>\s*(\.{0,2}/[^\s]+)", text, re.M):
        out.append(("replace => " + m.group(1), m.group(1), False))
    return out


def gemfile_deps(text):
    out = []
    for m in re.finditer(r"^\s*gem\s+['\"]([\w\-.]+)['\"]\s*(,\s*([^\n#]+))?", text, re.M):
        out.append((m.group(1), (m.group(3) or "").strip(), False))
    return out


def composer_deps(text):
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out = [(n, str(s), False) for n, s in (data.get("require") or {}).items() if "/" in n]
    out += [(n, str(s), True) for n, s in (data.get("require-dev") or {}).items() if "/" in n]
    return out


def maven_deps(text):
    out = []
    for m in re.finditer(r"<dependency>(.*?)</dependency>", text, re.S):
        block = m.group(1)
        g = re.search(r"<groupId>([^<]+)</groupId>", block)
        a = re.search(r"<artifactId>([^<]+)</artifactId>", block)
        v = re.search(r"<version>([^<]+)</version>", block)
        scope = re.search(r"<scope>([^<]+)</scope>", block)
        if g and a:
            out.append((f"{g.group(1)}:{a.group(1)}", v.group(1) if v else "", bool(scope and scope.group(1) == "test")))
    return out


def gradle_deps(text):
    out = []
    for m in re.finditer(r"\b(implementation|api|compile|runtimeOnly|compileOnly|testImplementation|kapt|ksp)\s*\(?\s*['\"]([\w.\-]+):([\w.\-]+):?([^'\"]*)['\"]", text):
        out.append((f"{m.group(2)}:{m.group(3)}", m.group(4), m.group(1).startswith("test")))
    return out


def csproj_deps(text):
    return [(m.group(1), m.group(2), False) for m in re.finditer(r"<PackageReference\s+Include=\"([^\"]+)\"\s+Version=\"([^\"]*)\"", text)]


def pubspec_deps(text):
    out, section = [], None
    for line in text.splitlines():
        top = re.match(r"^(dependencies|dev_dependencies)\s*:", line)
        if top:
            section = top.group(1)
            continue
        if re.match(r"^\S", line):
            section = None
        m = re.match(r"^  ([\w\-]+)\s*:\s*(.*)$", line)
        if section and m:
            out.append((m.group(1), m.group(2).strip(), section == "dev_dependencies"))
    return out


PARSERS = {
    "package.json": ("npm", npm_deps),
    "pyproject.toml": ("pypi", pyproject_deps),
    "Pipfile": ("pypi", lambda t: toml_table_deps(t, [("packages", False), ("dev-packages", True)])),
    "go.mod": ("go", gomod_deps),
    "Gemfile": ("rubygems", gemfile_deps),
    "composer.json": ("packagist", composer_deps),
    "Cargo.toml": ("crates", lambda t: toml_table_deps(t, [("dependencies", False), ("dev-dependencies", True), ("build-dependencies", False)])),
    "pom.xml": ("maven", maven_deps),
    "build.gradle": ("maven", gradle_deps),
    "build.gradle.kts": ("maven", gradle_deps),
    "pubspec.yaml": ("pub", pubspec_deps),
}


def classify(ecosystem, name, spec):
    """Return (issue, detail) tuples for one dependency."""
    issues = []
    s = spec.strip()
    if name == "<index option>":
        if s.startswith("--extra-index-url"):
            issues.append(("confusion", "--extra-index-url lets a public package shadow a private one; use one index or a proxy with namespacing"))
        return issues
    if re.search(r"git\+|git://|github:|gitlab:|bitbucket:|^https?://|\.tgz$|\.tar\.gz$|\.zip$|\"git\"|\"path\"|^file:|^link:|^\.{0,2}/|replace =>", s) or name.startswith(("git+", "replace =>")):
        issues.append(("source", f"installed from {s[:80]} instead of the registry"))
    elif ecosystem == "npm" and (s in ("*", "", "latest", "x", "next") or s.startswith((">=", ">"))):
        issues.append(("pin", f"version '{s or '(none)'}' accepts any future release"))
    elif ecosystem == "pypi" and (s == "" or s.startswith((">=", ">", "~=")) and "<" not in s or s == "*" or s == "\"*\""):
        issues.append(("pin", f"version '{s or '(none)'}' is not pinned"))
    elif ecosystem == "maven" and (s == "" or s in ("LATEST", "RELEASE", "latest.release", "latest.integration") or s.endswith("+") or s.startswith(("[", "("))):
        issues.append(("pin", f"dynamic or missing version '{s or '(none)'}'"))
    elif ecosystem in ("rubygems", "crates", "pub", "packagist") and s in ("", "*", "\"*\"", "any") or (ecosystem == "packagist" and s in ("*", "dev-master", "dev-main")):
        issues.append(("pin", f"version '{s or '(none)'}' accepts any release"))
    bad = KNOWN_BAD.get(ecosystem, {}).get(name)
    if bad:
        versions, why = bad
        plain = re.sub(r"^[\^~=v ]+", "", s)
        if versions is None or plain in versions:
            issues.append(("known", f"{name}: {why}"))
    alike = lookalike(name, ecosystem) if ecosystem in POPULAR else None
    if alike:
        issues.append(("typo", f"'{name}' is one edit away from the popular package '{alike}'"))
    return issues


def install_scripts(root):
    nm = os.path.join(root, "node_modules")
    found = []
    if not os.path.isdir(nm):
        return found
    for entry in sorted(os.listdir(nm)):
        dirs = [os.path.join(nm, entry, d) for d in sorted(os.listdir(os.path.join(nm, entry)))] if entry.startswith("@") and os.path.isdir(os.path.join(nm, entry)) else [os.path.join(nm, entry)]
        for d in dirs:
            pj = os.path.join(d, "package.json")
            if not os.path.isfile(pj):
                continue
            try:
                data = json.loads(read(pj))
            except ValueError:
                continue
            scripts = {k: v for k, v in (data.get("scripts") or {}).items() if k in ("preinstall", "install", "postinstall")}
            if scripts:
                found.append({"package": data.get("name", os.path.basename(d)), "version": data.get("version"), "scripts": scripts})
    return found[:200]


def main(argv=None):
    ap = argparse.ArgumentParser(description="SecurityKit dependency audit (offline).")
    ap.add_argument("--root", default=".")
    ap.add_argument("--include-dev", action="store_true", help="also report pinning issues in dev dependencies")
    ap.add_argument("--out")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)

    manifests, candidates, totals = [], [], {}
    has_update_bot = False
    npmrc_texts = []
    for rel_dir, names in walk(root):
        if rel_dir.startswith(".github/") and ({"dependabot.yml", "dependabot.yaml"} & names):
            has_update_bot = True
        if ({"renovate.json", "renovate.json5", ".renovaterc", ".renovaterc.json"} & names) and rel_dir in ("", ".github/", ".gitlab/"):
            has_update_bot = True
        if ".npmrc" in names:
            npmrc_texts.append((rel_dir + ".npmrc", read(os.path.join(root, rel_dir, ".npmrc"))))
        files = [n for n in names if n in PARSERS] + [n for n in names if n.endswith(".csproj")]
        files += [n for n in names if re.match(r"requirements[\w.\-]*\.(txt|in)$", n)]
        for name in sorted(set(files)):
            path = rel_dir + name
            if name.endswith(".csproj"):
                ecosystem, parse = "nuget", csproj_deps
            elif name.startswith("requirements"):
                ecosystem, parse = "pypi", requirements_deps
            else:
                ecosystem, parse = PARSERS[name]
            deps = parse(read(os.path.join(root, rel_dir, name)))
            locks = LOCKS.get(name, [])
            locked = any(l in names for l in locks) if locks else None
            if name == "pyproject.toml" and not deps:
                continue
            if name.startswith("requirements") and deps and all(re.match(r"==", d[1]) or d[0] == "<index option>" for d in deps):
                locked = True
            manifests.append({"file": path, "ecosystem": ecosystem, "dependencies": len(deps), "lockfile": locked})
            totals[ecosystem] = totals.get(ecosystem, 0) + len(deps)
            if locked is False and deps:
                candidates.append({"check": "DEPS-LOCK-001", "file": path, "dependency": None,
                                   "detail": f"no lockfile ({' / '.join(locks)}) next to {name}: installs are not reproducible"})
            for dep_name, spec, dev in deps:
                for issue, detail in classify(ecosystem, dep_name, spec):
                    if issue == "pin" and (dev and not args.include_dev or locked):
                        continue
                    check = {"pin": "DEPS-PIN-001", "source": "DEPS-SOURCE-001", "typo": "DEPS-TYPO-001",
                             "known": "DEPS-KNOWN-001", "confusion": "DEPS-CONFUSION-001"}[issue]
                    candidates.append({"check": check, "file": path, "dependency": dep_name, "spec": spec, "dev": dev, "detail": detail})

    for path, text in npmrc_texts:
        if re.search(r"(?m)^\s*ignore-scripts\s*=\s*true", text):
            continue
        scoped = re.findall(r"(?m)^\s*(@[\w\-]+):registry\s*=", text)
        if re.search(r"(?m)^\s*registry\s*=\s*https?://(?!registry\.npmjs\.org)", text) and not scoped:
            candidates.append({"check": "DEPS-CONFUSION-001", "file": path, "dependency": None,
                               "detail": "custom default registry without scope mapping: check private names cannot be claimed on the public registry"})

    scripts = install_scripts(root)
    for s in scripts:
        candidates.append({"check": "DEPS-SCRIPT-001", "file": "node_modules/" + s["package"] + "/package.json", "dependency": s["package"],
                           "spec": s.get("version"), "detail": "runs on install: " + "; ".join(f"{k}: {v}"[:120] for k, v in s["scripts"].items())})
    if manifests and not has_update_bot:
        candidates.append({"check": "DEPS-UPDATE-001", "file": None, "dependency": None,
                           "detail": "no Dependabot or Renovate configuration found"})

    # Tools are only listed, never run here: they send package names and versions to advisory databases.
    present = {os.path.basename(m["file"]) for m in manifests}
    for rel_dir, names in walk(root):
        present |= names & {lock for locks in LOCKS.values() for lock in locks}
    tools = [{"tool": exe, "command": command} for exe, command, needs in VULN_TOOLS
             if shutil.which(exe) and (needs is None or needs in present) and manifests]

    result = {
        "tool": "securitykit-deps-audit", "version": VERSION,
        "manifests": manifests, "dependency_counts": totals,
        "update_bot": has_update_bot,
        "vulnerability_tools_available": tools,
        "summary": {c: sum(1 for x in candidates if x["check"] == c) for c in sorted({x["check"] for x in candidates})},
        "candidates": candidates,
    }
    text = json.dumps(result, indent=2)
    if args.out:
        prepare_output(args.out)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"{len(manifests)} manifests, {sum(totals.values())} dependencies, {len(candidates)} candidates -> {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
SecurityKit security test gap finder (read-only, standard library only).

Finds the project's test files and frameworks, and for every endpoint (from sk-api's route discovery, or a routes
JSON you pass) works out whether some test calls it and whether that test looks like an
  unauth      request without credentials expecting 401
  authz       another user's / tenant's object, or a wrong role, expecting 403/404
  validation  invalid input expecting 400/422
test. Also counts security payload tests (injection, XSS, traversal) and whether CI runs the tests.

Matching is heuristic: a test "covers" a route when a string literal in the test looks like the route path, and a
signal counts when it appears within a few lines of that literal. Results are leads for the agent to verify.

  python3 test_gaps.py --root . --out .securitykit/test-gaps.json
  python3 test_gaps.py --root . --routes .securitykit/routes.json
"""

import argparse
import json
import os
import re
import subprocess
import sys

VERSION = "0.1.0"

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "target", "out", ".next", ".nuxt", "__pycache__", ".venv",
    "venv", "env", ".tox", ".mypy_cache", ".pytest_cache", ".securitykit", ".claude", ".codex", "coverage",
    ".idea", ".vscode", "bin", "obj", "Pods", ".gradle", ".terraform", "site-packages",
}
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "e2e", "integration"}
TEST_FILE_RE = re.compile(r"(\.(test|spec|e2e)\.[cm]?[jt]sx?$)|(^test_.*\.py$)|(_test\.(py|go)$)|(Tests?\.(java|kt|cs)$)|(IT\.java$)|(_spec\.rb$)|(Test\.php$)")
CODE_EXT = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx", ".py", ".go", ".java", ".kt", ".rb", ".php", ".cs"}
WINDOW = 6  # fallback when a file has no recognisable test blocks
# Lines that start a test case; signals only count inside the same test as the path literal.
TEST_START = re.compile(r"""^\s*((it|test|specify|scenario)(\.\w+)?\s*\(|(async\s+)?def\s+test_?\w*\s*\(|func\s+Test\w*\s*\(|@(Test|ParameterizedTest)|\[(Fact|Theory|Test|TestMethod)\]|(it|scenario|specify)\s+['"]|public\s+function\s+test\w*\s*\(|t\.Run\()""")

FRAMEWORKS = {
    "jest": r"\bfrom ['\"]@jest|\bjest\.(fn|mock)|\"jest\"", "vitest": r"from ['\"]vitest['\"]|\"vitest\"",
    "mocha": r"\"mocha\"|\bmocha\b", "node:test": r"from ['\"]node:test['\"]|require\(['\"]node:test['\"]\)",
    "supertest": r"supertest", "playwright": r"@playwright/test", "cypress": r"\bcy\.(visit|request)\(",
    "pytest": r"\bimport pytest\b|@pytest\.", "unittest": r"\bimport unittest\b|unittest\.TestCase",
    "django-test": r"from django\.test import|APITestCase|APIClient\(", "fastapi-testclient": r"TestClient\(",
    "flask-test": r"\.test_client\(\)", "junit": r"org\.junit", "spring-mockmvc": r"MockMvc|WebTestClient|TestRestTemplate",
    "rest-assured": r"io\.restassured", "go-testing": r"\"testing\"", "httptest": r"net/http/httptest",
    "rspec": r"\bRSpec\.describe|\bdescribe\b.*\bdo\s*$", "rails-request": r"ActionDispatch::IntegrationTest|type:\s*:request",
    "phpunit": r"PHPUnit\\|extends TestCase", "xunit": r"\[Fact\]|\[Theory\]", "nunit": r"\[Test\]|NUnit",
    "mstest": r"\[TestMethod\]", "WebApplicationFactory": r"WebApplicationFactory",
}

SIGNALS = {
    "unauth": r"\b401\b|HTTP_401|UNAUTHORIZED|[Uu]nauthori[sz]ed|isUnauthorized\(|[Uu]nauthenticated|without[ _-]?(a[ _-]?)?(token|auth|login|credentials|session)|no[ _-]?(token|auth)|anonymous|logged[ _-]?out|not[ _-]logged",
    "authz": r"\b403\b|HTTP_403|FORBIDDEN|[Ff]orbidden|isForbidden\(|other[ _-]?(user|tenant|account|org|customer)|another[ _-]?(user|tenant|account|org)|not[ _-]?(the[ _-]?)?owner|cross[ _-]?(tenant|user|account)|idor|wrong[ _-]?(role|user|tenant)|non[ _-]?admin|as[ _-]?(regular|normal)[ _-]?user|\buser_?b\b|\buserB\b|\bbob\b|\beve\b|\bmallory\b",
    "validation": r"\b400\b|\b422\b|HTTP_400|HTTP_422|BAD_REQUEST|UNPROCESSABLE|isBadRequest\(|isUnprocessableEntity|[Ii]nvalid|validation|ValidationError|too[ _-]?long|negative|malformed|missing[ _-]?(field|param)|required field",
    "payload": r"'\s*OR\s*'?1'?\s*=\s*'?1|<script|onerror\s*=|\.\./\.\./|__proto__|\{\{\s*7\s*\*\s*7\s*\}\}|\$\{\s*7\s*\*\s*7\s*\}|;\s*(cat|id|whoami)\b|\$ne|\$gt|javascript:|169\.254\.169\.254|file:///",
    "ratelimit": r"\b429\b|HTTP_429|TOO_MANY_REQUESTS|[Rr]ate[ _-]?limit|[Tt]oo many",
    "csrf": r"[Cc]srf|[Xx]srf",
}
SIGNAL_RE = {k: re.compile(v) for k, v in SIGNALS.items()}
FRAMEWORK_RE = {k: re.compile(v, re.M) for k, v in FRAMEWORKS.items()}
PATH_LITERAL = re.compile(r"""[`'"](/[A-Za-z0-9_\-./{}:<>$@%+]*[A-Za-z0-9_\-}{>])(\?[^`'"]*)?[`'"]""")
PARAM_SEG = re.compile(r"^(:\w+|\{[^}]*\}|<[^>]*>|\$\{[^}]*\}|\$\w+|\d+|[0-9a-fA-F-]{16,}|%\w|\*)$")
CI_FILES = re.compile(r"(^|/)(\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|\.circleci/config\.ya?ml|azure-pipelines\.ya?ml|Jenkinsfile|bitbucket-pipelines\.ya?ml)$")
CI_TEST_CMD = re.compile(r"(npm|pnpm|yarn|bun)\s+(run\s+)?test|npx\s+(jest|vitest|playwright)|pytest|python -m (pytest|unittest)|manage\.py test|go test|mvn\s+(-\S+\s+)*(test|verify)|gradlew?\s+(\S+\s+)*test|bundle exec (rspec|rails test)|rspec|phpunit|dotnet test|cargo test")


def norm_path(p):
    p = p.split("?")[0].rstrip("/") or "/"
    segs = [("*" if PARAM_SEG.match(s) else s.lower()) for s in p.split("/")]
    return "/".join(segs)


def same_route(route_norm, literal_norm):
    if route_norm == literal_norm:
        return True
    # Routers mounted under a prefix: '/orders/*' in code vs '/api/orders/*' in tests (or the reverse).
    a, b = sorted((route_norm, literal_norm), key=len)
    return a.count("/") >= 2 and b.endswith(a)


def block_bounds(starts, i, n):
    """[lo, hi) of the test case containing line i: from its start to the next test start."""
    if not starts:
        return max(0, i - WINDOW), min(n, i + WINDOW + 1)
    before = [s for s in starts if s <= i]
    after = [s for s in starts if s > i]
    return (before[-1] if before else 0), (after[0] if after else n)


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not (d.startswith(".") and d not in (".github", ".gitlab", ".circleci")))
        for f in sorted(filenames):
            yield os.path.relpath(os.path.join(dirpath, f), root).replace(os.sep, "/")


def read(root, rel):
    try:
        with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as fh:
            return fh.read(2_000_000)
    except OSError:
        return ""


def is_test_file(rel):
    parts = rel.split("/")
    name = parts[-1]
    if os.path.splitext(name)[1] not in CODE_EXT:
        return False
    return bool(TEST_FILE_RE.search(name)) or any(p in TEST_DIRS for p in parts[:-1])


def load_routes(root, routes_file, here, warnings):
    if routes_file:
        with open(routes_file, encoding="utf-8") as fh:
            data = json.load(fh)
        return data.get("routes", data if isinstance(data, list) else [])
    discover = os.path.join(here, "..", "..", "sk-api", "scripts", "discover_routes.py")
    if not os.path.isfile(discover):
        warnings.append("sk-api route discovery not installed; pass --routes or list endpoints manually")
        return []
    r = subprocess.run([sys.executable, discover, "--root", root], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        warnings.append("route discovery failed: " + r.stderr.strip()[:200])
        return []
    data = json.loads(r.stdout)
    warnings.extend("routes: " + w for w in data.get("warnings", []))
    return data.get("routes", [])


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="SecurityKit security test gap finder.")
    ap.add_argument("--root", default=".")
    ap.add_argument("--routes", help="routes JSON (sk-api discover_routes.py output); default: run it if installed")
    ap.add_argument("--out")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)
    warnings = []

    all_files = list(walk(root))
    test_files = [f for f in all_files if is_test_file(f)]
    frameworks, signal_totals, literals = set(), {k: 0 for k in SIGNALS}, []
    manifest_text = " ".join(read(root, f) for f in all_files if os.path.basename(f) in ("package.json", "pyproject.toml", "requirements.txt", "requirements-dev.txt", "go.mod", "pom.xml", "build.gradle", "build.gradle.kts", "Gemfile", "composer.json") or f.endswith(".csproj"))
    for name, rx in FRAMEWORK_RE.items():
        if rx.search(manifest_text):
            frameworks.add(name)
    for rel in test_files:
        text = read(root, rel)
        lines = text.splitlines()
        for name, rx in FRAMEWORK_RE.items():
            if rx.search(text):
                frameworks.add(name)
        line_signals = [{k for k, rx in SIGNAL_RE.items() if rx.search(ln)} for ln in lines]
        for sigs in line_signals:
            for k in sigs:
                signal_totals[k] += 1
        starts = [i for i, ln in enumerate(lines) if TEST_START.match(ln)]
        for i, ln in enumerate(lines):
            for m in PATH_LITERAL.finditer(ln):
                lo, hi = block_bounds(starts, i, len(lines))
                near = set().union(*line_signals[lo:hi]) if hi > lo else set()
                literals.append({"file": rel, "line": i + 1, "path": m.group(1), "norm": norm_path(m.group(1)), "signals": near})

    routes = load_routes(root, args.routes, here, warnings)
    rows = []
    for r in routes:
        rn = norm_path(r.get("path_normalized") or r.get("path") or "/")
        hits = [lit for lit in literals if same_route(rn, lit["norm"])]
        sig = set().union(*(h["signals"] for h in hits)) if hits else set()
        rows.append({
            "method": r.get("method"), "path": r.get("path"), "file": r.get("file"), "line": r.get("line"),
            "auth": r.get("auth"), "tested": bool(hits),
            "unauth_test": "unauth" in sig, "authz_test": "authz" in sig, "validation_test": "validation" in sig,
            "payload_test": "payload" in sig,
            "tests": sorted({f"{h['file']}:{h['line']}" for h in hits})[:10],
        })

    ci_files = [f for f in all_files if CI_FILES.search(f)]
    ci_runs_tests = any(CI_TEST_CMD.search(read(root, f)) for f in ci_files)
    with_mut = [r for r in rows if (r["method"] or "").upper() in ("POST", "PUT", "PATCH", "DELETE")]
    result = {
        "tool": "securitykit-test-gaps", "version": VERSION,
        "frameworks": sorted(frameworks), "test_files": len(test_files),
        "signal_lines": signal_totals,
        "ci": {"files": ci_files, "runs_tests": ci_runs_tests},
        "summary": {
            "routes": len(rows), "tested": sum(r["tested"] for r in rows),
            "protected_routes": sum(1 for r in rows if r["auth"] in ("yes", "unknown")),
            "protected_with_unauth_test": sum(1 for r in rows if r["auth"] in ("yes", "unknown") and r["unauth_test"]),
            "with_authz_test": sum(r["authz_test"] for r in rows),
            "mutating_routes": len(with_mut), "mutating_with_validation_test": sum(r["validation_test"] for r in with_mut),
        },
        "routes": rows,
        "untested_routes": [f"{r['method']} {r['path']} ({r['file']}:{r['line']})" for r in rows if not r["tested"]],
        "warnings": warnings,
    }
    text = json.dumps(result, indent=2)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        s = result["summary"]
        print(f"{len(test_files)} test files, {s['tested']}/{s['routes']} routes referenced by tests -> {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

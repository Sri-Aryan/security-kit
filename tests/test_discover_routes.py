"""Route discovery tests: the example app plus one fixture per supported framework."""

import json
import os
import re
import sys
import tempfile
import unittest

from sk_helpers import EXAMPLE, ROOT, SCRIPTS, read, run_python

sys.path.insert(0, SCRIPTS)
import discover_routes  # noqa: E402

FIXTURES = os.path.join(ROOT, "tests", "fixtures", "routes")


def routes(root):
    return {(r["method"], r["path"], r["auth"]) for r in discover_routes.discover(root)["routes"]}


def expected_inventory():
    """The 'Expected endpoint inventory' table in examples/vulnerable-api/EXPECTED.md."""
    text = read(os.path.join(EXAMPLE, "EXPECTED.md")).split("## Expected endpoint inventory", 1)[1]
    rows = re.findall(r"^\|\s*([A-Z]+)\s*\|\s*(/\S*)\s*\|\s*(yes|no|unknown)\s*\|", text, re.M)
    return set(rows)


class ExampleApp(unittest.TestCase):
    def test_inventory_matches_expected(self):
        expected = expected_inventory()
        self.assertGreaterEqual(len(expected), 12)
        self.assertEqual(routes(EXAMPLE), expected)

    def test_routes_point_at_handler_lines(self):
        result = discover_routes.discover(EXAMPLE)
        by_key = {(r["method"], r["path"]): r for r in result["routes"]}
        r = by_key[("GET", "/api/orders/:id")]
        self.assertEqual(r["file"], "routes/orders.js")
        line = read(os.path.join(EXAMPLE, r["file"])).splitlines()[r["line"] - 1]
        self.assertIn("router.get('/:id'", line)
        self.assertEqual(r["path_normalized"], "/api/orders/{id}")
        self.assertIn("requireAuth", " ".join(r["auth_signals"]))
        self.assertEqual(result["frameworks"], ["express"])
        self.assertEqual(result["warnings"], [])

    def test_cli_json_and_table(self):
        out = os.path.join(tempfile.mkdtemp(), "routes.json")
        r = run_python(os.path.join(SCRIPTS, "discover_routes.py"), "--root", EXAMPLE, "--out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(out, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["summary"]["routes"], len(data["routes"]))
        for key in ("method", "path", "file", "line", "handler", "framework", "auth", "auth_signals"):
            self.assertIn(key, data["routes"][0])
        t = run_python(os.path.join(SCRIPTS, "discover_routes.py"), "--root", EXAMPLE, "--format", "table")
        self.assertIn("/api/admin/stats", t.stdout)

    def test_bad_root(self):
        r = run_python(os.path.join(SCRIPTS, "discover_routes.py"), "--root", os.path.join(EXAMPLE, "nope"))
        self.assertEqual(r.returncode, 2)


class Frameworks(unittest.TestCase):
    def check(self, name, expected, frameworks):
        result = discover_routes.discover(os.path.join(FIXTURES, name))
        found = {(r["method"], r["path"], r["auth"]) for r in result["routes"]}
        self.assertEqual(found, set(expected), f"{name}: {sorted(found)}")
        self.assertEqual(result["frameworks"], frameworks)

    def test_express(self):
        self.check("express", [
            ("GET", "/api/users", "yes"), ("GET", "/api/users/:id", "yes"), ("DELETE", "/api/users/:id", "yes"),
            ("GET", "/health", "no"), ("GET", "/items", "no"), ("POST", "/items", "yes"), ("POST", "/login", "no"),
        ], ["express"])

    def test_nestjs(self):
        self.check("nestjs", [
            ("GET", "/api/orders", "no"), ("GET", "/api/orders/:id", "yes"), ("POST", "/api/orders/webhook", "no"),
        ], ["nestjs"])

    def test_fastapi(self):
        self.check("fastapi", [
            ("GET", "/api/items", "no"), ("GET", "/api/items/{item_id}", "yes"),
            ("DELETE", "/api/items/{item_id}", "yes"), ("GET", "/health", "no"), ("POST", "/me", "yes"),
        ], ["fastapi"])

    def test_flask(self):
        # register_blueprint(url_prefix="/admin") overrides Blueprint(url_prefix="/ignored")
        self.check("flask", [
            ("GET", "/", "no"), ("GET", "/admin/users", "no"), ("GET", "/profile", "yes"), ("POST", "/profile", "yes"),
        ], ["flask"])

    def test_django_drf(self):
        self.check("django", [
            ("ANY", "/shop/about/", "no"), ("GET", "/shop/open/", "no"),
            ("GET", "/shop/api/orders/", "yes"), ("POST", "/shop/api/orders/", "yes"),
            ("GET", "/shop/api/orders/{pk}/", "yes"), ("PUT", "/shop/api/orders/{pk}/", "yes"),
            ("PATCH", "/shop/api/orders/{pk}/", "yes"), ("DELETE", "/shop/api/orders/{pk}/", "yes"),
        ], ["django", "django-drf"])

    def test_spring(self):
        self.check("spring", [
            ("GET", "/api/orders/{id}", "unknown"), ("DELETE", "/api/orders/{id}", "yes"),
            ("POST", "/api/orders/search", "unknown"),
        ], ["spring"])

    def test_gin(self):
        self.check("gin", [
            ("GET", "/ping", "no"), ("GET", "/api/orders/:id", "yes"), ("DELETE", "/api/admin/users/:id", "yes"),
            ("POST", "/login", "no"),
        ], ["gin"])

    def test_go_net_http(self):
        self.check("nethttp", [
            ("GET", "/orders/{id}", "no"), ("ANY", "/admin", "yes"), ("ANY", "/health", "no"),
        ], ["net/http"])


class Helpers(unittest.TestCase):
    def test_normalize_path(self):
        n = discover_routes.normalize_path
        self.assertEqual(n("/orders/:id"), "/orders/{id}")
        self.assertEqual(n("/orders/<int:order_id>"), "/orders/{order_id}")
        self.assertEqual(n("/files/{id:\\d+}"), "/files/{id}")

    def test_blank_comments_keeps_urls_in_strings(self):
        src = "const u = 'http://x'; // app.get('/hidden')\n/* app.post('/also') */ app.get('/real')"
        out = discover_routes.blank_comments(src)
        self.assertIn("'http://x'", out)
        self.assertNotIn("/hidden", out)
        self.assertNotIn("/also", out)
        self.assertIn("/real", out)
        self.assertEqual(len(out), len(src))


if __name__ == "__main__":
    unittest.main()

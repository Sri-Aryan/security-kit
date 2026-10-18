"""
End-to-end dynamic probes against the running example app.

Skipped unless examples/vulnerable-api/node_modules exists (run `npm install` there first) and
Node 22.5+ is available. Starts the app on a free localhost port, runs dynamic_tests.py with real
user tokens, and checks the planted runtime issues are reported as candidates.
"""

import json
import os
import shutil
import socket
import subprocess
import time
import unittest
import urllib.request

from sk_helpers import EXAMPLE, SCRIPTS, run_python

HAS_DEPS = os.path.isdir(os.path.join(EXAMPLE, "node_modules", "express"))
NODE = shutil.which("node")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def post_json(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


@unittest.skipUnless(HAS_DEPS and NODE, "example app dependencies not installed (cd examples/vulnerable-api && npm install)")
class DynamicProbes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.proc = subprocess.Popen([NODE, "server.js"], cwd=EXAMPLE, env={**os.environ, "PORT": str(cls.port)},
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                urllib.request.urlopen(cls.base + "/health", timeout=1)
                break
            except OSError:
                time.sleep(0.2)
        else:
            cls.proc.kill()
            raise RuntimeError("example app did not start")
        cls.tokens = {
            "a": post_json(cls.base + "/api/auth/login", {"email": "alice@example.test", "password": "alice-pass"})["token"],
            "b": post_json(cls.base + "/api/auth/login", {"email": "bob@example.test", "password": "bob-pass"})["token"],
        }
        routes = run_python(os.path.join(SCRIPTS, "discover_routes.py"), "--root", EXAMPLE)
        cls.routes_file = os.path.join(EXAMPLE, ".securitykit", "routes.json")
        os.makedirs(os.path.dirname(cls.routes_file), exist_ok=True)
        with open(cls.routes_file, "w", encoding="utf-8") as fh:
            fh.write(routes.stdout)
        env = {**os.environ, "SK_TOKEN_A": cls.tokens["a"], "SK_TOKEN_B": cls.tokens["b"]}
        r = subprocess.run(
            [os.sys.executable, os.path.join(SCRIPTS, "dynamic_tests.py"), "--base-url", cls.base,
             "--routes", cls.routes_file, "--param", "id=101", "--login-path", "/api/auth/login",
             "--login-attempts", "8"],
            capture_output=True, text=True, encoding="utf-8", env=env, timeout=300)
        cls.result = json.loads(r.stdout) if r.returncode == 0 else {"error": r.stderr}

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=10)
        shutil.rmtree(os.path.join(EXAMPLE, ".securitykit"), ignore_errors=True)

    def candidate_ids(self):
        return {c["check_id"] for c in self.result.get("candidates", [])}

    def test_runs(self):
        self.assertNotIn("error", self.result)
        self.assertGreater(self.result["requests_sent"], 5)

    def test_finds_runtime_issues(self):
        ids = self.candidate_ids()
        print("\n\nDynamic candidates:", sorted(ids))
        for expected in ("API-CFG-001", "API-AUTHZ-001", "API-AUTHN-004", "API-AUTHN-001", "API-ERR-001"):
            self.assertIn(expected, ids)

    def test_evidence_has_request_and_redacted_tokens(self):
        dump = json.dumps(self.result)
        for tok in self.tokens.values():
            self.assertNotIn(tok, dump, "token leaked into output")
        for c in self.result["candidates"]:
            self.assertIn("status", c["request"])
            self.assertTrue(c["request"]["responseExcerpt"].startswith("HTTP "))


if __name__ == "__main__":
    unittest.main()

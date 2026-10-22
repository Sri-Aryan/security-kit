"""
Scanner output must be byte-identical between runs.

Agents cache the conversation by exact prefix: a scan result that changes on every run (timestamps, random IDs,
unordered sets) can never be served from cache, in a re-run or in parallel sub-agents. This guards the shared engine
and the helper scripts that print into the conversation.
"""

import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EXAMPLE = os.path.join(ROOT, "examples", "vulnerable-api")
# A spread of rule sets: absence and multiline rules, macros, redaction, path filters.
SCANNERS = ["sk-secrets", "sk-xss", "sk-ai-code", "sk-defaults", "sk-baas", "sk-nextjs"]


def run(args):
    r = subprocess.run([sys.executable] + args, capture_output=True, text=True, cwd=ROOT)
    return r.returncode, r.stdout


class ScanOutputIsStable(unittest.TestCase):
    def assert_stable(self, args):
        first, second = run(args), run(args)
        self.assertEqual(first[0], 0, f"{args} failed")
        self.assertEqual(first, second, f"output differs between runs: {args}")

    def test_rule_engine(self):
        for skill in SCANNERS:
            with self.subTest(skill=skill):
                self.assert_stable([os.path.join(ROOT, "skills", skill, "scripts", "sk_scan.py"), "--root", EXAMPLE, "--include-tests"])

    def test_phantom_deps(self):
        self.assert_stable([os.path.join(ROOT, "skills", "sk-ai-code", "scripts", "phantom_deps.py"), "--root", ROOT])

    def test_audit_plan(self):
        self.assert_stable([os.path.join(ROOT, "skills", "sk-audit", "scripts", "audit.py"), "plan", "--root", EXAMPLE,
                            "--skills-dir", os.path.join(ROOT, "skills")])


if __name__ == "__main__":
    unittest.main()

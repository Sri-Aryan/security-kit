"""
Semgrep rule tests.

tests/semgrep/* carry annotations on the line before the code they describe:
    // ruleid: rule-a, rule-b   -> these rules MUST match the next line
    // ok: rule-a               -> rule-a must NOT match the next line
Any match on a line without a matching "ruleid" annotation is a false positive and fails.
Skipped (not failed) when Semgrep is not installed.
"""

import os
import re
import unittest
from collections import defaultdict

from sk_helpers import ROOT, checklist_ids, read, copy_to_temp, find_semgrep, rule_ids_and_checks, run_static

FIXTURES = os.path.join(ROOT, "tests", "semgrep")
ANNOTATION = re.compile(r"(?:#|//)\s*(ruleid|ok):\s*([\w\-, ]+)")


def parse_annotations():
    expected, forbidden = set(), set()
    for name in sorted(os.listdir(FIXTURES)):
        lines = read(os.path.join(FIXTURES, name)).splitlines()
        pending = []
        for i, line in enumerate(lines, start=1):
            m = ANNOTATION.search(line)
            if m:
                pending.append((m.group(1), [r.strip() for r in m.group(2).split(",") if r.strip()]))
                continue
            for kind, rules in pending:
                for r in rules:
                    (expected if kind == "ruleid" else forbidden).add((name, i, r))
            pending = []
    return expected, forbidden


class RuleMetadata(unittest.TestCase):
    def test_every_rule_maps_to_a_checklist_id(self):
        ids = checklist_ids()
        rules = rule_ids_and_checks()
        self.assertGreater(len(rules), 20)
        for rid, check in rules.items():
            self.assertIsNotNone(check, f"{rid} has no metadata.check_id")
            self.assertIn(check, ids, f"{rid} -> {check} is not in checklist.md")

    def test_every_rule_has_a_positive_test(self):
        expected, _ = parse_annotations()
        tested = {r for _, _, r in expected}
        untested = sorted(set(rule_ids_and_checks()) - tested)
        self.assertEqual(untested, [], f"rules without a 'ruleid:' test case: {untested}")


@unittest.skipUnless(find_semgrep(), "Semgrep not installed (pip install semgrep)")
class RuleBehaviour(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = run_static(copy_to_temp(FIXTURES))

    def test_scan_succeeded(self):
        self.assertEqual(self.result.get("semgrep"), "ok", self.result)
        self.assertEqual(self.result.get("errors"), [], self.result.get("errors"))

    def test_annotations(self):
        expected, forbidden = parse_annotations()
        actual = {(r["file"], r["line"], r["rule"]) for r in self.result["results"]}
        missed = sorted(expected - actual)
        false_pos = sorted(actual - expected)
        explicit_ok_violations = sorted(actual & forbidden)
        report = defaultdict(list)
        for f, l, r in missed:
            report["missed (ruleid not matched)"].append(f"{f}:{l} {r}")
        for f, l, r in false_pos:
            report["unexpected match"].append(f"{f}:{l} {r}")
        msg = "\n".join(f"{k}:\n  " + "\n  ".join(v) for k, v in report.items())
        self.assertEqual(explicit_ok_violations, [], msg)
        self.assertEqual((missed, false_pos), ([], []), msg)

    def test_results_carry_snippets_and_check_ids(self):
        for r in self.result["results"]:
            self.assertRegex(r["check_id"], r"^API-[A-Z]+-\d{3}$")
            self.assertIn(f"{r['line']:>5} |", r["snippet"])


if __name__ == "__main__":
    unittest.main()

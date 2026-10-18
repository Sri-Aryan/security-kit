"""
Detection coverage on examples/vulnerable-api.

Parses the planted-issue table in EXPECTED.md, runs the shipped static scan, and reports which
planted issues are caught and which are missed. Fails if any issue that names a Semgrep detector
is missed. Prints the coverage table either way.
"""

import os
import re
import unittest

from sk_helpers import EXAMPLE, checklist_ids, copy_to_temp, find_semgrep, read, run_static


def planted_issues():
    text = read(os.path.join(EXAMPLE, "EXPECTED.md"))
    table = text.split("## Planted issues", 1)[1].split("\n## ", 1)[0]
    rows = []
    for line in table.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 6 and cells[0].isdigit():
            num, check, title, file, anchor, detector = cells
            rows.append({
                "num": int(num), "check_id": check, "title": title, "file": file,
                "anchor": anchor.strip("`"), "detector": detector,
            })
    return rows


def anchor_line(row):
    lines = read(os.path.join(EXAMPLE, *row["file"].split("/"))).splitlines()
    hits = [i for i, l in enumerate(lines, start=1) if row["anchor"] in l]
    return hits


class PlantedIssues(unittest.TestCase):
    def test_answer_key_is_consistent(self):
        rows = planted_issues()
        self.assertGreaterEqual(len(rows), 12, "brief requires at least 12 planted issues")
        ids = checklist_ids()
        for row in rows:
            self.assertIn(row["check_id"], ids, f"#{row['num']} uses unknown check {row['check_id']}")
            self.assertEqual(len(anchor_line(row)), 1, f"#{row['num']} anchor must match exactly one line: {row['anchor']}")
            self.assertRegex(row["detector"], r"^(semgrep:sk-[\w-]+|agent)$")


@unittest.skipUnless(find_semgrep(), "Semgrep not installed (pip install semgrep)")
class Coverage(unittest.TestCase):
    def test_static_detection_coverage(self):
        result = run_static(copy_to_temp(EXAMPLE))
        self.assertEqual(result.get("semgrep"), "ok", result)
        rows = planted_issues()
        caught, missed, agent_only, used = [], [], [], set()
        for row in rows:
            line = anchor_line(row)[0]
            if row["detector"] == "agent":
                agent_only.append(row)
                continue
            rule = row["detector"].split(":", 1)[1]
            hit = next((r for r in result["results"]
                        if r["rule"] == rule and r["file"] == row["file"]
                        and (r["line"] <= line <= r["end_line"] or abs(r["line"] - line) <= 1)), None)
            if hit:
                used.add((hit["rule"], hit["file"], hit["line"]))
                self.assertEqual(hit["check_id"], row["check_id"], f"#{row['num']} rule tagged with wrong check")
            (caught if hit else missed).append(row)

        extra = [r for r in result["results"] if (r["rule"], r["file"], r["line"]) not in used]

        print("\n\nDetection coverage on examples/vulnerable-api")
        print(f"  Semgrep-detectable: {len(caught)}/{len(caught) + len(missed)} caught")
        for row in caught:
            print(f"    [caught] #{row['num']:<2} {row['check_id']:<15} {row['title'][:70]}")
        for row in missed:
            print(f"    [MISSED] #{row['num']:<2} {row['check_id']:<15} {row['title'][:70]}")
        for row in agent_only:
            print(f"    [agent ] #{row['num']:<2} {row['check_id']:<15} {row['title'][:70]}")
        print(f"  Other candidates (agent should confirm or reject): {len(extra)}")
        for r in extra:
            print(f"    {r['check_id']:<15} {r['file']}:{r['line']} ({r['rule']})")

        self.assertEqual([r["num"] for r in missed], [], "planted issues missed by their Semgrep rule")


class CheckIds(unittest.TestCase):
    """Every check ID referenced anywhere in the kit exists in checklist.md (catches drift when the real checklist lands)."""

    def test_all_referenced_ids_exist(self):
        ids = checklist_ids()
        here = os.path.dirname(os.path.abspath(__file__))
        root = os.path.dirname(here)
        sources = [
            os.path.join(root, "skills", "sk-api", "rules", "api.yml"),
            os.path.join(root, "skills", "sk-api", "SKILL.md"),
            os.path.join(root, "skills", "sk-api", "scripts", "dynamic_tests.py"),
            os.path.join(EXAMPLE, "EXPECTED.md"),
        ]
        missing = {}
        for src in sources:
            for ref in set(re.findall(r"\bAPI-[A-Z]+-\d{3}\b", read(src))):
                if ref not in ids:
                    missing.setdefault(ref, []).append(os.path.relpath(src, root))
        self.assertEqual(missing, {}, "check IDs referenced but not in checklist.md")


if __name__ == "__main__":
    unittest.main()

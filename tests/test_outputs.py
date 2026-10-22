"""SecurityKit output stays out of git: .securitykit/.gitignore, .git/info/exclude, and the shared-script copies."""

import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from sk_helpers import ROOT

sys.path.insert(0, os.path.join(ROOT, "shared", "scripts"))
import sk_outputs  # noqa: E402

GIT = shutil.which("git")


def git(cwd, *args):
    return subprocess.run(["git", "-C", cwd] + list(args), capture_output=True, text=True)


def ignored(repo, rel):
    return git(repo, "check-ignore", "-q", rel).returncode == 0


def new_repo():
    repo = tempfile.mkdtemp(prefix="sk-out-")
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "test@example.test")
    git(repo, "config", "user.name", "test")
    return repo


def prepare(path):
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        sk_outputs.prepare_output(path)
    return err.getvalue()


@unittest.skipUnless(GIT, "git not installed")
class KeepsReportsOutOfGit(unittest.TestCase):
    def test_scan_output_and_reports_are_ignored_but_suppressions_are_not(self):
        repo = new_repo()
        note = prepare(os.path.join(repo, ".securitykit", "api-scan.json"))
        self.assertIn("keeping reports out of git", note)
        for rel in [".securitykit/api-scan.json", ".securitykit/api-report.json", ".securitykit/.gitignore",
                    "security-report-api.md", "security-report-audit.md", "sub/security-report-api.md"]:
            self.assertTrue(ignored(repo, rel), f"{rel} should be ignored")
        for rel in [".securitykit/ignore.json", ".securitykit/manifest.json", "security.md", "src/app.js"]:
            self.assertFalse(ignored(repo, rel), f"{rel} should not be ignored")
        # The project's tracked .gitignore is never touched.
        self.assertFalse(os.path.exists(os.path.join(repo, ".gitignore")))

    def test_second_run_changes_nothing(self):
        repo = new_repo()
        prepare(os.path.join(repo, ".securitykit", "a.json"))
        exclude = os.path.join(repo, ".git", "info", "exclude")
        with open(exclude, encoding="utf-8") as fh:
            before = fh.read()
        self.assertEqual(before.count(sk_outputs.REPORT_GLOB), 1)
        self.assertEqual(prepare(os.path.join(repo, ".securitykit", "b.json")), "")
        with open(exclude, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), before)

    def test_existing_project_rule_is_respected(self):
        repo = new_repo()
        with open(os.path.join(repo, ".gitignore"), "w", encoding="utf-8") as fh:
            fh.write("security-report*.md\n")
        prepare(os.path.join(repo, "security-report-audit.md"))
        exclude = os.path.join(repo, ".git", "info", "exclude")
        if os.path.exists(exclude):
            with open(exclude, encoding="utf-8") as fh:
                self.assertNotIn(sk_outputs.EXCLUDE_BLOCK, fh.read())
        self.assertTrue(os.path.exists(os.path.join(repo, ".securitykit", ".gitignore")))

    def test_user_edited_state_gitignore_is_kept(self):
        repo = new_repo()
        os.makedirs(os.path.join(repo, ".securitykit"))
        custom = os.path.join(repo, ".securitykit", ".gitignore")
        with open(custom, "w", encoding="utf-8") as fh:
            fh.write("*.json\n")
        prepare(os.path.join(repo, ".securitykit", "x.json"))
        with open(custom, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "*.json\n")

    def test_warns_about_reports_already_committed(self):
        repo = new_repo()
        with open(os.path.join(repo, "security-report-api.md"), "w", encoding="utf-8") as fh:
            fh.write("# report\n")
        git(repo, "add", "security-report-api.md")
        git(repo, "commit", "-q", "-m", "add report")
        note = prepare(os.path.join(repo, ".securitykit", "api-scan.json"))
        self.assertIn("already committed", note)
        self.assertIn("security-report-api.md", note)

    def test_outside_a_repository(self):
        folder = tempfile.mkdtemp(prefix="sk-out-nogit-")
        prepare(os.path.join(folder, ".securitykit", "x.json"))
        self.assertTrue(os.path.exists(os.path.join(folder, ".securitykit", ".gitignore")))

    def test_other_output_paths_are_left_alone(self):
        folder = tempfile.mkdtemp(prefix="sk-out-other-")
        out = os.path.join(folder, "out", "routes.json")
        self.assertEqual(prepare(out), "")
        self.assertTrue(os.path.isdir(os.path.dirname(out)))
        self.assertFalse(os.path.exists(os.path.join(folder, ".securitykit")))

    def test_shipped_script_protects_on_write(self):
        repo = new_repo()
        with open(os.path.join(repo, "app.py"), "w", encoding="utf-8") as fh:
            fh.write("print('hi')\n")
        script = os.path.join(ROOT, "skills", "sk-audit", "scripts", "audit.py")
        r = subprocess.run([sys.executable, script, "plan", "--root", repo, "--out",
                            os.path.join(repo, ".securitykit", "audit-plan.json")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(ignored(repo, ".securitykit/audit-plan.json"))
        self.assertTrue(ignored(repo, "security-report-audit.md"))


class SharedCopies(unittest.TestCase):
    def test_every_skill_ships_current_shared_scripts(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "sync_shared.py"), "--check"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_cli_writes_the_same_gitignore(self):
        with open(os.path.join(ROOT, "src", "manifest.js"), encoding="utf-8") as fh:
            js = fh.read()
        for line in sk_outputs.STATE_GITIGNORE.splitlines():
            self.assertIn(line, js)


if __name__ == "__main__":
    unittest.main()

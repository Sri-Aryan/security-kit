"""Shared helpers for the Python test suite (stdlib only)."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL = os.path.join(ROOT, "skills", "sk-api")
SCRIPTS = os.path.join(SKILL, "scripts")
RULES = os.path.join(SKILL, "rules", "api.yml")
CHECKLIST = os.path.join(SKILL, "checklist.md")
EXAMPLE = os.path.join(ROOT, "examples", "vulnerable-api")


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def find_semgrep():
    """Semgrep on PATH, or SEMGREP=<path>. Returns None if unavailable."""
    explicit = os.environ.get("SEMGREP")
    if explicit and os.path.exists(explicit):
        return explicit
    return shutil.which("semgrep")


def run_static(target):
    """Run the shipped run_static script (bash if available, else PowerShell) and return its JSON."""
    env = dict(os.environ)
    sg = find_semgrep()
    if sg:
        env["PATH"] = os.path.dirname(sg) + os.pathsep + env.get("PATH", "")
    bash = shutil.which("bash")
    if bash:
        cmd = [bash, os.path.join(SCRIPTS, "run_static.sh"), target]
    else:
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
               os.path.join(SCRIPTS, "run_static.ps1"), target]
    out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", env=env, timeout=900)
    try:
        return json.loads(out.stdout)
    except ValueError:
        raise AssertionError(f"run_static did not print JSON.\nstdout:\n{out.stdout[-2000:]}\nstderr:\n{out.stderr[-2000:]}")


def copy_to_temp(src):
    """Semgrep skips tests/ by default, so scan fixtures from a neutral temp dir."""
    dest = os.path.join(tempfile.mkdtemp(prefix="sk-test-"), os.path.basename(src))
    shutil.copytree(src, dest, ignore=shutil.ignore_patterns("node_modules", "__pycache__", ".securitykit"))
    return dest


def rule_ids_and_checks():
    """{rule_id: check_id} parsed from rules/api.yml without a YAML library."""
    text = read(RULES)
    out = {}
    for block in re.split(r"\n  - id: ", text)[1:]:
        rid = block.split("\n", 1)[0].strip()
        m = re.search(r"check_id:\s*([A-Z0-9-]+)", block)
        out[rid] = m.group(1) if m else None
    return out


def checklist_ids():
    return set(re.findall(r"\bAPI-[A-Z]+-\d{3}\b", read(CHECKLIST)))


def run_python(script, *args, cwd=None):
    return subprocess.run([sys.executable, script, *args], capture_output=True, text=True,
                          encoding="utf-8", cwd=cwd, timeout=300)

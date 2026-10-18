#!/usr/bin/env python3
"""
SecurityKit rule engine (static, read-only, standard library only).

Every SecurityKit skill ships an identical copy of this file next to its own rules (JSON). Rules describe
security *concepts* as text patterns that work across languages; every hit is a CANDIDATE that the agent
confirms or rejects by reading the code.

  python3 sk_scan.py --root . --rules ../rules            # scan, print JSON
  python3 sk_scan.py --rules ../rules --self-test         # check every rule against its own examples
  python3 sk_scan.py --rules ../rules --list              # list rules

Rule file format (JSON):
  {
    "macros": {"SRC_JS": "req\\.(query|body|params)"},        # reused as {{SRC_JS}} inside patterns
    "rules": [{
      "id": "unique-id", "check_id": "XXX-YYY-001", "title": "...",
      "files": ["js", "py"],              # groups: js py java kt go rb php cs rs scala ex swift dart code web config
                                         #         env docker shell tf sql any  (or ".ext" / "Filename")
      "pattern": "regex",                # per line, unless "multiline": true (whole file)
      "flags": "i",                      # i, m, s
      "near": {"pattern": "regex", "lines": 5},       # must also match within +/- N lines
      "not_near": {"pattern": "regex", "lines": 5},   # must NOT match within +/- N lines
      "file_requires": "regex", "file_excludes": "regex",
      "path_includes": "regex", "path_excludes": "regex",    # on the relative path
      "entropy": {"group": 1, "min": 3.5},                   # Shannon entropy of a capture group
      "redact": true | 2,                                    # mask the match (or a group) in snippets
      "type": "absence", "when": "regex", "missing": "regex", "scope": "file" | "project",
      "confidence": "HIGH" | "MEDIUM" | "LOW", "note": "...",
      "examples": {"match": ["code...", {"b64": "..."}], "no_match": ["code..."]}   # b64: encoded fake secrets
    }]
  }

Suppression: a `securitykit-ignore` comment on the line (or the line above), optionally naming the check ID;
or `.securitykit/ignore.json` = {"ignore": [{"check_id", "path" (glob), "line"?, "reason", "expires"?}]}.
Entries without a reason, or past their expiry date, are not honoured.
"""

import argparse
import base64
import bisect
import datetime
import fnmatch
import json
import math
import os
import re
import subprocess
import sys
from collections import Counter

VERSION = "0.1.0"

GROUPS = {
    "js": {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte"},
    "py": {".py", ".pyw"},
    "java": {".java"},
    "kt": {".kt", ".kts"},
    "go": {".go"},
    "rb": {".rb", ".rake"},
    "php": {".php"},
    "cs": {".cs"},
    "rs": {".rs"},
    "scala": {".scala"},
    "ex": {".ex", ".exs"},
    "swift": {".swift"},
    "dart": {".dart"},
    "web": {".html", ".htm", ".ejs", ".hbs", ".handlebars", ".jinja", ".j2", ".erb", ".twig", ".vue", ".svelte", ".jsx", ".tsx", ".cshtml", ".jsp"},
    "config": {".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml", ".env", ".config", ".plist"},
    "shell": {".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"},
    "tf": {".tf", ".tfvars", ".hcl"},
    "sql": {".sql"},
}
GROUPS["code"] = set().union(*(GROUPS[g] for g in ("js", "py", "java", "kt", "go", "rb", "php", "cs", "rs", "scala", "ex", "swift", "dart")))
SPECIAL_NAMES = {
    "docker": re.compile(r"^(Dockerfile(\..*)?|.*\.dockerfile|docker-compose.*\.ya?ml|compose\.ya?ml|Containerfile)$", re.I),
    "env": re.compile(r"^\.env(\..*)?$|.*\.env$", re.I),
}
SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "target", "out", ".next", ".nuxt", "__pycache__", ".venv",
    "venv", "env", ".tox", ".mypy_cache", ".pytest_cache", ".securitykit", ".claude", ".codex", "coverage",
    ".idea", ".vscode", "bin", "obj", "Pods", ".gradle", ".terraform", "bower_components", "site-packages",
}
# Agent/editor config folders (MCP servers, tool permissions), walked only with --agent-dirs. Their installed
# skills/plugins are third-party content (including SecurityKit's own rule examples), so those stay skipped.
AGENT_DIRS = {".claude", ".codex", ".agents", ".cursor", ".vscode", ".gemini", ".windsurf", ".roo", ".continue", ".amazonq"}
AGENT_SKIP = {"skills", "plugins", "commands", "agents"}
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "testdata", "e2e", "fixtures", "__mocks__"}
TEST_FILE_RE = re.compile(r"(\.(test|spec)\.[cm]?[jt]sx?$)|(^test_.*\.py$)|(_test\.(py|go)$)|(Tests?\.(java|kt|cs)$)|(_spec\.rb$)")
MAX_BYTES = 2_000_000
MAX_LINE = 4000
MAX_HITS_PER_RULE = 200
CHECK_ID = r"[A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)+-\d{3}"
IGNORE_RE = re.compile(r"securitykit-ignore(?::\s*(" + CHECK_ID + r"))?", re.I)


# --------------------------------------------------------------------------- rules

class Rule:
    def __init__(self, raw, macros, source):
        self.raw = raw
        self.id = raw["id"]
        self.check_id = raw["check_id"]
        self.title = raw["title"]
        self.source = source
        self.type = raw.get("type", "match")
        self.files = raw.get("files", ["code"])
        self.confidence = raw.get("confidence", "MEDIUM")
        self.note = raw.get("note", "")
        self.multiline = raw.get("multiline", False)
        self.scope = raw.get("scope", "file")
        flags = 0
        for ch in raw.get("flags", ""):
            flags |= {"i": re.I, "m": re.M, "s": re.S}[ch]
        self.flags = flags

        def rx(key, sub=None):
            node = raw.get(key) if sub is None else (raw.get(key) or {}).get(sub)
            if node is None:
                return None
            return re.compile(expand(node, macros, self.id), flags)

        self.pattern = rx("pattern")
        self.when = rx("when")
        self.missing = rx("missing")
        self.near = rx("near", "pattern")
        self.near_lines = (raw.get("near") or {}).get("lines", 3)
        self.not_near = rx("not_near", "pattern")
        self.not_near_lines = (raw.get("not_near") or {}).get("lines", 3)
        self.file_requires = rx("file_requires")
        self.file_excludes = rx("file_excludes")
        self.path_includes = re.compile(raw["path_includes"], re.I) if raw.get("path_includes") else None
        self.path_excludes = re.compile(raw["path_excludes"], re.I) if raw.get("path_excludes") else None
        self.entropy = raw.get("entropy")
        self.redact = raw.get("redact")  # True (whole match) or a group number: mask it in snippets
        if self.type == "match" and not self.pattern:
            raise ValueError(f"rule {self.id}: 'pattern' is required")
        if self.type == "absence" and not (self.when and self.missing):
            raise ValueError(f"rule {self.id}: absence rules need 'when' and 'missing'")

    def applies_to(self, rel, groups):
        if not any(f in groups or f == os.path.splitext(rel)[1].lower() or f == os.path.basename(rel) for f in self.files):
            return False
        if self.path_includes and not self.path_includes.search(rel):
            return False
        if self.path_excludes and self.path_excludes.search(rel):
            return False
        return True


def expand(pattern, macros, rule_id):
    for _ in range(5):
        new = re.sub(r"\{\{(\w+)\}\}", lambda m: f"(?:{macros[m.group(1)]})" if m.group(1) in macros else m.group(0), pattern)
        if new == pattern:
            break
        pattern = new
    left = re.findall(r"\{\{(\w+)\}\}", pattern)
    if left:
        raise ValueError(f"rule {rule_id}: unknown macro(s) {left}")
    return pattern


def load_rules(paths):
    rules, files = [], []
    for p in paths:
        if os.path.isdir(p):
            files += [os.path.join(p, f) for f in sorted(os.listdir(p)) if f.endswith(".json")]
        else:
            files.append(p)
    seen = set()
    for f in files:
        with open(f, encoding="utf-8") as fh:
            data = json.load(fh)
        macros = data.get("macros", {})
        for raw in data.get("rules", []):
            r = Rule(raw, macros, os.path.basename(f))
            if r.id in seen:
                raise ValueError(f"duplicate rule id {r.id}")
            seen.add(r.id)
            rules.append(r)
    return rules


# --------------------------------------------------------------------------- files

def file_groups(rel):
    name = os.path.basename(rel)
    ext = os.path.splitext(name)[1].lower()
    groups = {g for g, exts in GROUPS.items() if ext in exts}
    for g, rx in SPECIAL_NAMES.items():
        if rx.match(name):
            groups.add(g)
    if "env" in groups:
        groups.add("config")
    groups.add("any")
    return groups


def walk(root, include_tests, agent_dirs=False):
    for dirpath, dirnames, filenames in os.walk(root):
        in_agent_dir = agent_dirs and os.path.basename(dirpath) in AGENT_DIRS
        dirnames[:] = sorted(d for d in dirnames
                             if (agent_dirs and d in AGENT_DIRS)
                             or (d not in SKIP_DIRS and not (d.startswith(".") and d not in (".github", ".gitlab", ".circleci"))
                                 and (include_tests or d not in TEST_DIRS) and not (in_agent_dir and d in AGENT_SKIP)))
        for f in sorted(filenames):
            if not include_tests and TEST_FILE_RE.search(f):
                continue
            if f.endswith((".min.js", ".map", ".lock")) or f in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
                continue
            full = os.path.join(dirpath, f)
            text = read_text(full)
            if text is not None:
                yield os.path.relpath(full, root).replace(os.sep, "/"), text


def walk_listed(root, rel_paths):
    """Yield (rel, text) for an explicit list of files under root, e.g. the files changed in a diff."""
    for rel in sorted(rel_paths):
        full = os.path.normpath(os.path.join(root, rel))
        if not full.startswith(os.path.normpath(root) + os.sep) or not os.path.isfile(full):
            continue
        text = read_text(full)
        if text is not None:
            yield rel, text


def read_text(full):
    """File contents as text, or None for large, unreadable or binary files."""
    try:
        if os.path.getsize(full) > MAX_BYTES:
            return None
        with open(full, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", "replace")


def git_tracked(root):
    try:
        r = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, timeout=60)
        if r.returncode == 0:
            return set(r.stdout.decode("utf-8", "replace").split("\0"))
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


# --------------------------------------------------------------------------- matching

def redact(line, m, group):
    """Mask a matched secret: keep the first 4 characters."""
    g = 0 if group is True else int(group)
    try:
        secret = m.group(g)
    except IndexError:
        secret = m.group(0)
    if not secret or len(secret) < 6:
        return line
    return line.replace(secret, secret[:4] + "...[redacted]")


def window_has(rx, lines, i, n):
    lo, hi = max(0, i - n), min(len(lines), i + n + 1)
    return any(rx.search(lines[j]) for j in range(lo, hi))


def suppressed_inline(lines, i, check_id):
    for j in (i, i - 1):
        if 0 <= j < len(lines):
            m = IGNORE_RE.search(lines[j])
            if m and (not m.group(1) or m.group(1).upper() == check_id):
                return True
    return False


def match_rule_in_text(rule, text, lines=None):
    """[(line_index, match)] for a match rule against one file's text."""
    if rule.file_requires and not rule.file_requires.search(text):
        return []
    if rule.file_excludes and rule.file_excludes.search(text):
        return []
    lines = lines if lines is not None else text.splitlines()
    out = []
    if rule.multiline:
        starts = [0] + [m.end() for m in re.finditer(r"\n", text)]
        for m in rule.pattern.finditer(text):
            out.append((bisect.bisect_right(starts, m.start()) - 1, m))
    else:
        for i, line in enumerate(lines):
            if len(line) > MAX_LINE:
                continue
            m = rule.pattern.search(line)
            if m:
                out.append((i, m))
    kept = []
    for i, m in out:
        if rule.near and not window_has(rule.near, lines, i, rule.near_lines):
            continue
        if rule.not_near and window_has(rule.not_near, lines, i, rule.not_near_lines):
            continue
        if rule.entropy:
            g = rule.entropy.get("group", 0)
            try:
                val = m.group(g) or ""
            except IndexError:
                val = m.group(0)
            if entropy(val) < rule.entropy.get("min", 3.5):
                continue
        kept.append((i, m))
    return kept


def first_line(rx, text):
    m = rx.search(text)
    return text.count("\n", 0, m.start()) if m else 0


# --------------------------------------------------------------------------- ignore file

def load_ignores(root, warnings):
    path = os.path.join(root, ".securitykit", "ignore.json")
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            entries = json.load(fh).get("ignore", [])
    except (OSError, ValueError) as e:
        warnings.append(f".securitykit/ignore.json unreadable: {e}")
        return []
    today = datetime.date.today().isoformat()
    valid = []
    for e in entries:
        if not e.get("reason"):
            warnings.append(f"ignore entry without a reason is not honoured: {e}")
        elif e.get("expires") and str(e["expires"]) < today:
            warnings.append(f"ignore entry expired on {e['expires']}: {e.get('check_id')} {e.get('path')}")
        else:
            valid.append(e)
    return valid


def ignored_by(entries, cand):
    for e in entries:
        if e.get("check_id") not in (None, "*", cand["check_id"]) and e.get("rule") != cand["rule"]:
            continue
        if e.get("path") and not fnmatch.fnmatch(cand["file"] or "", e["path"]):
            continue
        if e.get("line") and e["line"] != cand["line"]:
            continue
        return e
    return None


# --------------------------------------------------------------------------- scan

def scan(root, rules, include_tests=False, agent_dirs=False, only_files=None):
    """only_files: set of relative paths (forward slashes) to scan instead of the whole tree (diff reviews).
    Project-scope absence rules are skipped then: a partial file set cannot prove a control is missing."""
    root = os.path.abspath(root)
    warnings = []
    if only_files is None:
        files = list(walk(root, include_tests, agent_dirs))
    else:
        files = list(walk_listed(root, only_files))
    tracked = git_tracked(root)
    ignores = load_ignores(root, warnings)
    cands, suppressed = [], []
    per_rule = Counter()

    def add(rule, rel, i, lines, extra_note="", m=None):
        snippet = lines[i] if 0 <= i < len(lines) else ""
        if rule.redact and m is not None:
            snippet = redact(snippet, m, rule.redact)
        cand = {
            "rule": rule.id, "check_id": rule.check_id, "title": rule.title, "file": rel, "line": i + 1,
            "snippet": snippet.strip()[:240],
            "confidence": rule.confidence, "note": (rule.note + (" " + extra_note if extra_note else "")).strip(),
            "git_tracked": (rel in tracked) if tracked is not None else None,
        }
        if suppressed_inline(lines, i, rule.check_id):
            suppressed.append({**cand, "by": "inline comment"})
            return
        hit = ignored_by(ignores, cand)
        if hit:
            suppressed.append({**cand, "by": "ignore.json", "reason": hit.get("reason")})
            return
        per_rule[rule.id] += 1
        if per_rule[rule.id] == MAX_HITS_PER_RULE + 1:
            warnings.append(f"rule {rule.id}: more than {MAX_HITS_PER_RULE} hits, rest omitted")
        if per_rule[rule.id] <= MAX_HITS_PER_RULE:
            cands.append(cand)

    prepared = [(rel, text, text.splitlines(), file_groups(rel)) for rel, text in files]
    for rule in rules:
        targets = [(rel, text, lines) for rel, text, lines, groups in prepared if rule.applies_to(rel, groups)]
        if rule.type == "match":
            for rel, text, lines in targets:
                seen = set()
                for i, m in match_rule_in_text(rule, text, lines):
                    if i not in seen:
                        seen.add(i)
                        add(rule, rel, i, lines, m=m)
        elif rule.type == "absence":
            when_files = [(rel, text, lines) for rel, text, lines in targets if rule.when.search(text)
                          and not (rule.file_requires and not rule.file_requires.search(text))
                          and not (rule.file_excludes and rule.file_excludes.search(text))]
            if rule.scope == "project":
                if only_files is not None:
                    continue
                if when_files and not any(rule.missing.search(t) for _, t, _ in targets):
                    for rel, text, lines in when_files[:5]:
                        add(rule, rel, first_line(rule.when, text), lines, "(nothing matching the control was found anywhere in the project)")
            else:
                for rel, text, lines in when_files:
                    if not rule.missing.search(text):
                        add(rule, rel, first_line(rule.when, text), lines)

    cands.sort(key=lambda c: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(c["confidence"], 3), c["check_id"], c["file"], c["line"]))
    counts = Counter(c["check_id"] for c in cands)
    return {
        "tool": "securitykit-sk-scan", "version": VERSION, "root": ".",
        "files_scanned": len(files), "rules": len(rules),
        "counts_by_check": dict(sorted(counts.items())),
        "candidates": cands, "suppressed": suppressed, "warnings": warnings,
    }


# --------------------------------------------------------------------------- self-test

def sample_name(rule):
    for f in rule.files:
        if f.startswith("."):
            return "sample" + f
        if f in GROUPS and f not in ("code", "any"):
            return "sample" + sorted(GROUPS[f])[0]
        if f == "docker":
            return "Dockerfile"
        if f == "env":
            return ".env"
        if f[:1].isupper():
            return f
    return "sample.js"


def self_test(rules, checklist_ids=None):
    failures, checked = [], 0
    for rule in rules:
        if checklist_ids is not None and rule.check_id not in checklist_ids:
            failures.append(f"{rule.id}: check_id {rule.check_id} not in checklist.md")
        ex = rule.raw.get("examples") or {}
        if not ex.get("match"):
            failures.append(f"{rule.id}: no positive example")
        name = sample_name(rule)
        for kind in ("match", "no_match"):
            for sample in ex.get(kind, []):
                if isinstance(sample, dict) and "b64" in sample:
                    # Fake credentials are stored encoded so this repository does not trip secret scanners.
                    sample = base64.b64decode(sample["b64"]).decode("utf-8")
                checked += 1
                if rule.type == "absence":
                    hit = (bool(rule.when.search(sample)) and not rule.missing.search(sample)
                           and not (rule.file_requires and not rule.file_requires.search(sample)))
                else:
                    hit = bool(match_rule_in_text(rule, sample))
                if hit != (kind == "match"):
                    failures.append(f"{rule.id}: expected {'a match' if kind == 'match' else 'no match'} for {sample!r} (as {name})")
    return checked, failures


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="SecurityKit rule engine.")
    ap.add_argument("--root", default=".")
    ap.add_argument("--rules", action="append", help="rules file or directory (default: ../rules next to this script)")
    ap.add_argument("--out")
    ap.add_argument("--include-tests", action="store_true")
    ap.add_argument("--agent-dirs", action="store_true", help="also walk agent/editor config folders (.claude, .cursor, .vscode, ...)")
    ap.add_argument("--only-files", help="file listing relative paths (one per line) to scan instead of the whole tree")
    ap.add_argument("--check", action="append", default=[], help="only rules for these check IDs or prefixes (e.g. AUTH-PWD)")
    ap.add_argument("--self-test", action="store_true", help="verify every rule against its examples")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)
    paths = args.rules or [os.path.join(here, "..", "rules")]
    try:
        rules = load_rules(paths)
    except (OSError, ValueError, re.error) as e:
        print(f"error: invalid rules: {e}", file=sys.stderr)
        return 2
    if args.check:
        rules = [r for r in rules if any(r.check_id == c or r.check_id.startswith(c) for c in args.check)]

    if args.list:
        for r in rules:
            print(f"{r.check_id:<16} {r.confidence:<6} {r.id:<44} {r.title}")
        return 0
    if args.self_test:
        checklist = os.path.join(here, "..", "checklist.md")
        ids = None
        if os.path.exists(checklist):
            with open(checklist, encoding="utf-8") as fh:
                ids = set(re.findall(r"\b" + CHECK_ID + r"\b", fh.read()))
        checked, failures = self_test(rules, ids)
        for f in failures:
            print("FAIL", f)
        print(f"{len(rules)} rules, {checked} examples, {len(failures)} failure(s)")
        return 1 if failures else 0
    if not os.path.isdir(args.root):
        print(f"error: not a directory: {args.root}", file=sys.stderr)
        return 2
    only = None
    if args.only_files:
        with open(args.only_files, encoding="utf-8") as fh:
            only = {ln.strip().replace("\\", "/") for ln in fh if ln.strip()}
    result = scan(args.root, rules, args.include_tests, args.agent_dirs, only)
    text = json.dumps(result, indent=2)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"{result['files_scanned']} files, {len(result['candidates'])} candidates -> {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

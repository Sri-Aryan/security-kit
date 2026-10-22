#!/usr/bin/env python3
"""
SecurityKit fuzz target finder (read-only, standard library only).

Lists the project's languages, existing property-testing / fuzzing tooling, and candidate fuzz targets: functions
that parse, decode, deserialize, tokenize, sanitize, normalize or validate data, ranked by how fuzz-worthy they look
(byte/offset arithmetic, recursion, regexes, unsafe/native code). For each target it reports whether a test or fuzz
harness already mentions it. Every target is a CANDIDATE for the agent to confirm.

  python3 fuzz_targets.py --root . --out .securitykit/fuzz-targets.json
"""

import argparse
import json
import os
import re
import sys
from collections import Counter

from sk_outputs import prepare_output

VERSION = "0.1.0"

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "target", "out", ".next", ".nuxt", "__pycache__", ".venv",
    "venv", "env", ".tox", ".mypy_cache", ".pytest_cache", ".securitykit", ".claude", ".codex", "coverage",
    ".idea", ".vscode", "bin", "obj", "Pods", ".gradle", ".terraform", "site-packages", "third_party", "external",
}
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "e2e", "fuzz", "fuzzing", "testdata", "benches"}
TEST_FILE_RE = re.compile(r"(\.(test|spec)\.[cm]?[jt]sx?$)|(^test_.*\.py$)|(_test\.(py|go)$)|(Tests?\.(java|kt|cs)$)|(_spec\.rb$)|(Test\.php$)|fuzz", re.I)
LANG = {
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".mts": "typescript", ".py": "python", ".go": "go", ".java": "java", ".kt": "kotlin",
    ".rs": "rust", ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".rb": "ruby", ".php": "php", ".cs": "csharp", ".swift": "swift",
}
MEMORY_UNSAFE = {"c", "cpp"}

TARGET_NAME = re.compile(
    r"(?i)^(parse|decode|deserial|unmarshal|unpack|unserial|tokeni[sz]|lex|scan|read_?(header|frame|packet|record|chunk|message|varint)|"
    r"from_?(bytes|buffer|str|string|json|xml|yaml|wire)|load_?s?$|import|convert|transform|render|sanitiz|normali[sz]|"
    r"escape|unescape|validate|canonicali[sz]|expand|interpolat|format_?\w*|split_?\w*|extract|inflate|decompress|"
    r"untar|unzip|resolve_?path|url_?parse|parse\w*)"
)
DEF_RE = {
    "javascript": re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:function\s*\*?\s*(\w+)\s*\(|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>|\w+\s*=>))"),
    "python": re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\("),
    "go": re.compile(r"^func\s+(?:\([^)]*\)\s*)?(\w+)\s*\("),
    "java": re.compile(r"^\s*(?:(?:public|private|protected|static|final|synchronized)\s+)+[\w<>\[\],\s]+\s+(\w+)\s*\("),
    "kotlin": re.compile(r"^\s*(?:(?:public|private|internal|protected|override|suspend|inline)\s+)*fun\s+(?:<[^>]+>\s*)?(?:\w+\.)?(\w+)\s*\("),
    "rust": re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:async\s+)?fn\s+(\w+)"),
    "c": re.compile(r"^(?!\s*(?:if|for|while|switch|return)\b)[A-Za-z_][\w\s\*]*?[\s\*](\w+)\s*\([^;]*$"),
    "ruby": re.compile(r"^\s*def\s+(?:self\.)?(\w+[?!]?)"),
    "php": re.compile(r"^\s*(?:(?:public|private|protected|static)\s+)*function\s+(\w+)\s*\("),
    "csharp": re.compile(r"^\s*(?:(?:public|private|protected|internal|static|async|override|virtual)\s+)+[\w<>\[\],?\s]+\s+(\w+)\s*\("),
    "swift": re.compile(r"^\s*(?:(?:public|private|internal|static|mutating)\s+)*func\s+(\w+)"),
}
DEF_RE["typescript"] = DEF_RE["javascript"]
DEF_RE["cpp"] = DEF_RE["c"]

RISK = [
    ("byte/offset handling", 3, re.compile(r"struct\.(un)?pack|int\.from_bytes|memoryview|\bBuffer\.|\.read(U?Int|Float|Double|BigU?Int)\d*|DataView|Uint8Array|binary\.(Read|BigEndian|LittleEndian)|encoding/binary|ByteBuffer|DataInputStream|BitConverter|Span<byte>|from_(le|be)_bytes|\bmemcpy\b|\bmemmove\b|\bstrcpy\b|\bsprintf\b|\[\s*\w+\s*\+\s*\d+\s*\]|\boffset\b|\bpos\s*\+=|\bcursor\b")),
    ("unsafe/native code", 3, re.compile(r"\bunsafe\b|\bmalloc\(|\bfree\(|\bctypes\b|\bcgo\b|import \"C\"|Marshal\.(Copy|ReadByte)|\bfixed\s*\(|\bstackalloc\b")),
    ("regex on input", 1, re.compile(r"re\.(compile|match|search|sub|findall)|new RegExp|\.match\(|\.replace\(/|regexp\.|Pattern\.compile|Regex\(")),
    ("loops over input", 1, re.compile(r"\bwhile\b|\bfor\b")),
    ("decoding/escaping", 1, re.compile(r"decode|encode|unescape|base64|utf-?8|charCodeAt|codePointAt|\bord\(|\bchr\(")),
    ("format parser", 2, re.compile(r"(?i)xml|yaml|json|csv|protobuf|msgpack|asn\.?1|der\b|pem\b|zip|tar|gzip|png|jpeg|pdf|markdown|html|url|uri|mime|multipart|header")),
]

TOOLING = {
    "fast-check (JS property tests)": r"fast-check|\bfc\.(assert|property)\(",
    "Jazzer.js": r"@jazzer\.js", "jsfuzz": r"\bjsfuzz\b",
    "Hypothesis (Python)": r"\bhypothesis\b|@given\(", "Atheris (Python)": r"\batheris\b",
    "Schemathesis (API)": r"\bschemathesis\b", "RESTler (API)": r"\brestler\b",
    "Go native fuzzing": r"func\s+Fuzz\w*\s*\(\s*\w+\s+\*testing\.F", "gopter": r"leanovate/gopter",
    "Jazzer (JVM)": r"com\.code_intelligence\.jazzer|@FuzzTest", "jqwik": r"net\.jqwik|@Property\b",
    "junit-quickcheck": r"junit-quickcheck", "Kotest property": r"io\.kotest\.property",
    "cargo-fuzz / libfuzzer-sys": r"libfuzzer-sys|fuzz_target!", "proptest": r"\bproptest\b", "quickcheck (Rust)": r"\bquickcheck\b",
    "libFuzzer": r"LLVMFuzzerTestOneInput", "AFL/AFL++": r"\bafl-(fuzz|clang|gcc)|__AFL_", "honggfuzz": r"honggfuzz",
    "OSS-Fuzz": r"oss-fuzz|ossfuzz", "ClusterFuzzLite / CIFuzz": r"clusterfuzzlite|cifuzz|google/oss-fuzz/infra/cifuzz",
    "SharpFuzz (.NET)": r"SharpFuzz", "FsCheck / CsCheck": r"\bFsCheck\b|\bCsCheck\b", "rspec-propcheck / rantly": r"\bpropcheck\b|\brantly\b",
    "php-fuzzer": r"nikic/php-fuzzer", "sanitizers": r"-fsanitize=(address|undefined|memory|fuzzer)",
}
TOOLING_RE = {k: re.compile(v) for k, v in TOOLING.items()}
CI_FILES = re.compile(r"(^|/)(\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|\.circleci/config\.ya?ml|azure-pipelines\.ya?ml|Jenkinsfile|\.clusterfuzzlite/.*)$")
CI_FUZZ = re.compile(r"(?i)-fuzz(time)?\b|cargo\s+fuzz|cifuzz|clusterfuzzlite|atheris|jazzer|schemathesis|hypothesis|fast-check|afl-fuzz|libfuzzer")
FUZZ_MARK = re.compile(r"(?i)fuzz|@given|fc\.property|fc\.assert|proptest|quickcheck|@Property|forAll|checkAll")


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not (d.startswith(".") and d not in (".github", ".gitlab", ".circleci", ".clusterfuzzlite")))
        for f in sorted(filenames):
            yield os.path.relpath(os.path.join(dirpath, f), root).replace(os.sep, "/")


def read(root, rel):
    try:
        if os.path.getsize(os.path.join(root, rel)) > 1_500_000:
            return ""
        with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def is_test(rel):
    parts = rel.split("/")
    return bool(TEST_FILE_RE.search(parts[-1])) or any(p.lower() in TEST_DIRS for p in parts[:-1])


def main(argv=None):
    ap = argparse.ArgumentParser(description="SecurityKit fuzz target finder.")
    ap.add_argument("--root", default=".")
    ap.add_argument("--max", type=int, default=60, help="maximum targets to report (default 60)")
    ap.add_argument("--out")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)

    files = list(walk(root))
    langs = Counter(LANG[os.path.splitext(f)[1].lower()] for f in files if os.path.splitext(f)[1].lower() in LANG)
    tooling, test_texts, targets = set(), {}, []
    for rel in files:
        ext = os.path.splitext(rel)[1].lower()
        name = os.path.basename(rel)
        if ext not in LANG and name not in ("package.json", "requirements.txt", "requirements-dev.txt", "pyproject.toml", "Cargo.toml", "go.mod", "pom.xml", "build.gradle", "build.gradle.kts", "Gemfile", "composer.json", "Makefile", "CMakeLists.txt", "project.yaml") and not rel.endswith(".csproj") and not CI_FILES.search(rel):
            continue
        text = read(root, rel)
        for tool, rx in TOOLING_RE.items():
            if rx.search(text):
                tooling.add(tool)
        if ext not in LANG:
            continue
        if is_test(rel):
            test_texts[rel] = text
            continue
        lang = LANG[ext]
        lines = text.splitlines()
        defs = [(i, DEF_RE[lang].match(ln)) for i, ln in enumerate(lines)]
        defs = [(i, m) for i, m in defs if m]
        for n, (i, m) in enumerate(defs):
            fname = next((g for g in m.groups() if g), None)
            if not fname or not TARGET_NAME.match(fname) or fname.lower() in ("main", "init"):
                continue
            end = defs[n + 1][0] if n + 1 < len(defs) else len(lines)
            body = "\n".join(lines[i + 1:min(end, i + 80)])  # the function body, up to the next definition
            score, reasons = 1, []
            for label, weight, rx in RISK:
                if rx.search(body):
                    score += weight
                    reasons.append(label)
            if re.search(r"\b" + re.escape(fname) + r"\s*\(", body):
                score += 2
                reasons.append("recursion")
            if lang in MEMORY_UNSAFE:
                score += 3
                reasons.append("memory-unsafe language")
            targets.append({"name": fname, "file": rel, "line": i + 1, "language": lang, "score": score, "reasons": reasons})

    word = {}
    for t in targets:
        rx = word.setdefault(t["name"], re.compile(r"\b" + re.escape(t["name"]) + r"\b"))
        mentioned = [f for f, txt in test_texts.items() if rx.search(txt)]
        t["unit_tests"] = mentioned[:5]
        t["fuzz_or_property_tests"] = [f for f in mentioned if FUZZ_MARK.search(test_texts[f])][:5]
    targets.sort(key=lambda t: (-t["score"], bool(t["fuzz_or_property_tests"]), t["file"], t["line"]))

    ci_files = [f for f in files if CI_FILES.search(f)]
    result = {
        "tool": "securitykit-fuzz-targets", "version": VERSION,
        "languages": dict(langs.most_common()),
        "tooling": sorted(tooling),
        "ci": {"files": ci_files, "runs_fuzzing": any(CI_FUZZ.search(read(root, f)) for f in ci_files)},
        "summary": {"targets": len(targets), "with_fuzz_or_property_test": sum(1 for t in targets if t["fuzz_or_property_tests"]),
                    "with_any_test": sum(1 for t in targets if t["unit_tests"])},
        "targets": targets[:args.max],
    }
    text = json.dumps(result, indent=2)
    if args.out:
        prepare_output(args.out)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"{len(targets)} candidate targets ({result['summary']['with_fuzz_or_property_test']} with fuzz/property tests) -> {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

# Fuzzing and property testing guide

Generated inputs find the bugs hand-written tests don't think of: crashes, hangs, memory corruption, ReDoS,
round-trip mismatches and validator bypasses. Use the project's language-native tools; add no new language runtime.

## Choose the technique

| Target | Technique | Tools |
|---|---|---|
| Pure function on strings/objects (validator, sanitizer, encoder, small parser) | Property-based test inside the normal test suite | fast-check (JS/TS), Hypothesis (Python), jqwik / Kotest (JVM), proptest / quickcheck (Rust), FsCheck / CsCheck (.NET), rapid / gopter (Go), PropCheck / Rantly (Ruby) |
| Complex parser, binary format, decompressor, protocol handler, anything in C/C++/`unsafe` | Coverage-guided fuzzing | Go `func FuzzX(f *testing.F)`, cargo-fuzz, libFuzzer/AFL++ (+ sanitizers), Atheris (Python), Jazzer (JVM), Jazzer.js, SharpFuzz |
| HTTP API with an OpenAPI/GraphQL schema | Schema-based API fuzzing (localhost only) | Schemathesis, RESTler |

## Good properties (FUZZ-PROP-001, FUZZ-ORACLE-001)

- **Round-trip**: `decode(encode(x)) == x`; `parse(format(x)) == x`.
- **Idempotence**: `sanitize(sanitize(x)) == sanitize(x)`; `normalize` likewise.
- **Total**: for any input, the function returns or raises only the documented error type (no `TypeError`, `IndexError`, panic, segfault).
- **Security invariants**: sanitized HTML contains no `<script`/`on*=`; a normalized path stays under the base folder;
  a validated URL's host is in the allow-list; an escaped SQL identifier matches `^[A-Za-z0-9_]+$`.
- **Differential**: your parser and a reference implementation agree (e.g. your URL parser vs the platform's).

```text
property "path stays in root":  for any string s: resolve(ROOT, s) is ROOT or starts with ROOT + "/"  (or raises)
property "decoder is total":     for any bytes b: decode(b) returns Frame or raises DecodeError
```

## Harness hygiene (FUZZ-LIMIT-001, FUZZ-SAN-001, FUZZ-CORPUS-001)

Per-input timeout (e.g. libFuzzer `-timeout=5`), RSS limit, max input length; deterministic harness (no network, no
clock, no global state); sanitizers on for native code; seed corpus from real samples and test fixtures; a dictionary
of format tokens; minimise and commit each crasher under a regression test.

## Running (FUZZ-CI-001)

Property tests run with the unit tests (fixed seed in CI, larger example counts nightly). Fuzz harnesses: 30–120
seconds per target in CI (`go test -fuzz=FuzzX -fuzztime=60s`, ClusterFuzzLite in PRs), hours in a scheduled job or
OSS-Fuzz for open-source projects. API fuzzing only against a local or dedicated test environment.

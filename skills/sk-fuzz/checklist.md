# Fuzzing and property testing checklist

Source of truth for `sk-fuzz` check IDs. Covers automated, generated-input testing of the code that handles untrusted
data (parsers, decoders, deserializers, validators, sanitizers, protocol and file-format handlers, API input
handling) in any language: property-based testing, coverage-guided fuzzing and schema-based API fuzzing. Based on the
OWASP Fuzzing guidance (WSTG, OWASP Fuzzing project) and the OSS-Fuzz / ClusterFuzzLite practices.
`references/guide.md` gives harness patterns per language.

Columns: **Mode** S = static. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| FUZZ-TARGET-001 | Code that parses or transforms untrusted input is identified and prioritised (custom parsers, binary/offset handling, recursion, regexes, memory-unsafe or `unsafe` code first) | S | Medium | A04 | CWE-20 |
| FUZZ-PROP-001 | Pure parsing, encoding, validation and sanitization functions have property-based tests with meaningful properties (round-trip, idempotence, never throws an unexpected error type, output invariants) | S | Medium | A04 | CWE-20 |
| FUZZ-HARNESS-001 | Complex or memory-unsafe parsers and file/protocol handlers have coverage-guided fuzz harnesses (Go native fuzzing, libFuzzer/cargo-fuzz, Atheris, Jazzer, Jazzer.js, SharpFuzz) | S | High | A04 | CWE-119 |
| FUZZ-ORACLE-001 | Harnesses check more than "no crash": decoded output re-encodes, invariants hold, differential checks against a reference implementation, security properties (sanitizer output contains no active markup) | S | Medium | A04 | CWE-20 |
| FUZZ-LIMIT-001 | Harnesses use per-input timeouts, memory limits and input-size caps so hangs, ReDoS, decompression bombs and memory blow-ups are reported as bugs | S | Medium | A04 | CWE-400 |
| FUZZ-SAN-001 | Native code is fuzzed with sanitizers (ASan, UBSan, MSan) and Rust/Go race or overflow checks where applicable | S | High | A04 | CWE-787 |
| FUZZ-CORPUS-001 | Seed corpora and dictionaries exist for each harness; every crasher found is minimised and committed as a regression test | S | Low | A04 | CWE-1059 |
| FUZZ-API-001 | HTTP APIs with a schema (OpenAPI/GraphQL) are fuzzed against a local test instance (Schemathesis, RESTler) checking for 5xx errors and schema violations | S | Medium | A04 | CWE-20 |
| FUZZ-CI-001 | Short fuzz/property runs execute in CI on every change, and long runs are scheduled (nightly job, OSS-Fuzz, ClusterFuzzLite) with findings triaged | S | Low | A04 | CWE-1059 |

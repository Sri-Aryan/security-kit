# Input validation checklist

Source of truth for `sk-validation` check IDs. Covers how an application validates untrusted input at its entry
points, in any language: schema validation on every endpoint, server-side (not only client-side) checks, strict
schemas that reject unknown fields, mass assignment, type confusion (loose comparisons, arrays where strings were
expected), numeric ranges, formats (email, URL, phone, dates), canonicalization, and allow-lists. Validation is the
first layer; output encoding and parameterization (`sk-inject`, `sk-xss`) still apply. Based on the OWASP Input
Validation and Mass Assignment cheat sheets and API3/API6. `references/guide.md` shows schema patterns.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP Top 10 2021 / API Top 10 2023.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| VAL-SCHEMA-001 | Every external input (body, query, path, headers, cookies, messages, files' metadata) is validated with a schema/validator at the boundary; failures return 400/422 | S | Medium | A03 | CWE-20 |
| VAL-SERVER-001 | Validation happens on the server; client-side validation (HTML attributes, front-end forms) is UX only | S+D | High | A04 | CWE-602 |
| VAL-STRICT-001 | Schemas reject or strip unknown fields and the validated object (not the raw input) is what the code uses | S | Medium | API3 | CWE-915 |
| VAL-MASS-001 | No mass assignment: models are never created/updated from the whole request; writable fields are allow-listed | S+D | High | API3 | CWE-915 |
| VAL-TYPE-001 | Types are enforced: no loose comparisons with input, no arrays/objects accepted where strings or numbers are expected | S | Medium | A03 | CWE-843 |
| VAL-NUMERIC-001 | Numbers are checked for range, integer-ness and NaN/Infinity before use; money uses decimal types | S | Medium | A04 | CWE-1284 |
| VAL-FORMAT-001 | Formats (email, URL, phone, dates, IDs) are validated with well-tested libraries or strict anchored patterns, with length limits | S | Low | A03 | CWE-20 |
| VAL-CANON-001 | Input is canonicalized once before validation (Unicode normalization, decoding, case folding for identifiers) so lookalike or double-encoded values can't bypass checks or create duplicate accounts | S | Medium | A03 | CWE-180 |
| VAL-ALLOW-001 | Enumerated values (sort fields, statuses, roles, file types, locales) are checked against allow-lists, not deny-lists | S | Medium | A03 | CWE-184 |

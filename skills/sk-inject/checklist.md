# Injection checklist

Source of truth for `sk-inject` check IDs. Covers every class where untrusted data is interpreted as code or
syntax by another interpreter, in any language: SQL, NoSQL, OS commands and arguments, code evaluation, server-side
templates, expression languages, LDAP, XPath/XML, HTTP headers (CRLF), logs, regular expressions, path traversal and
spreadsheet formulas. Based on the OWASP Injection Prevention, SQL Injection Prevention, Query Parameterization, OS
Command Injection Defense, LDAP Injection Prevention, XML External Entity Prevention and Logging cheat sheets.
XSS is covered by `sk-xss`, deserialization by `sk-deserialize`, SSRF by `sk-ssrf`; `sk-database` covers
data-access design. `references/guide.md` gives the safe API per class.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP Top 10 2021 (A03 Injection) / API 2023.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| INJ-SQL-001 | SQL is never built from input by concatenation, formatting or interpolation; bound parameters are used | S+D | Critical | A03 | CWE-89 |
| INJ-SQL-002 | Dynamic identifiers (columns, tables, sort direction) come from allow-lists | S | High | A03 | CWE-89 |
| INJ-ORM-001 | ORM escape hatches (raw, literal, extra, unsafe) never receive interpolated input | S | High | A03 | CWE-89 |
| INJ-NOSQL-001 | NoSQL queries reject operator objects from input and avoid server-side JavaScript | S+D | High | A03 | CWE-943 |
| INJ-CMD-001 | No shell command is built from input; processes are started with argument arrays and no shell | S+D | Critical | A03 | CWE-78 |
| INJ-ARG-001 | Input passed as arguments to programs cannot become options (`--`, leading `-` rejected) | S | Medium | A03 | CWE-88 |
| INJ-CODE-001 | Input never reaches `eval`, `exec`, `Function`, `vm`, script engines or dynamic imports/requires | S | Critical | A03 | CWE-95 |
| INJ-SSTI-001 | Input is never used as a template source (server-side template injection) | S+D | Critical | A03 | CWE-1336 |
| INJ-EL-001 | Input is never evaluated by expression languages (SpEL, OGNL, MVEL, EL, JEXL) | S | Critical | A03 | CWE-917 |
| INJ-LDAP-001 | LDAP filters and DNs escape input with the library's encoder | S | High | A03 | CWE-90 |
| INJ-XPATH-001 | XPath/XQuery use parameters or escaped input | S | High | A03 | CWE-643 |
| INJ-XXE-001 | XML parsers have DTDs/external entities disabled | S | High | A05 | CWE-611 |
| INJ-HDR-001 | Input placed in response headers (including `Location`, `Set-Cookie`) has CR/LF removed | S | Medium | A03 | CWE-113 |
| INJ-LOG-001 | Input written to logs is encoded (CR/LF, control characters) to prevent log forging | S | Low | A09 | CWE-117 |
| INJ-REGEX-001 | Input is not compiled as a regular expression (ReDoS / regex injection), or is escaped and time-bounded | S | Medium | A03 | CWE-1333 |
| INJ-PATH-001 | File paths built from input are confined to an allowed base directory (path traversal) | S+D | High | A01 | CWE-22 |
| INJ-CSV-001 | Data exported to CSV/spreadsheets neutralizes formula prefixes (`=`, `+`, `-`, `@`, tab, CR) | S | Low | A03 | CWE-1236 |
| INJ-TEST-001 | Tests send injection payloads to each confirmed sink and assert they are treated as data | S | Low | A03 | CWE-1125 |
